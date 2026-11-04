mod s3;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use std::{env, process, thread};

use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

// The CA that issues agent certificates, and this collector's certificate and key.
const CA: &str = "/etc/panopticon-collector/ca.pem";
const CERT: &str = "/etc/panopticon-collector/cert.pem";
const KEY: &str = "/etc/panopticon-collector/key.pem";
// Connections served at once. Each holds its body until S3 has it, so memory stays below
// WORKERS * MAX_BODY; further connections wait in the listen backlog.
const WORKERS: usize = 64;
const MAX_BODY: usize = 16 << 20;
const MAX_HEAD: usize = 8 << 10;
const TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let [listen, dest] = args.as_slice() else {
        eprintln!("usage: panopticon-collector <listen-addr> s3://<bucket>[/<prefix>]");
        process::exit(2);
    };
    let store = Arc::new(s3::Store::new(dest));
    let tls = Arc::new(tls_config());
    let listener = TcpListener::bind(listen).unwrap_or_else(|err| panic!("{listen}: {err}"));
    let (conns, queue) = mpsc::sync_channel::<TcpStream>(0);
    let queue = Arc::new(Mutex::new(queue));
    for _ in 0..WORKERS {
        let (queue, tls, store) = (queue.clone(), tls.clone(), store.clone());
        thread::spawn(move || {
            loop {
                serve(queue.lock().unwrap().recv().unwrap(), &tls, &store);
            }
        });
    }
    eprintln!("listening on {listen}, writing to {dest}");
    for sock in listener.incoming() {
        match sock {
            Ok(sock) => conns.send(sock).unwrap(),
            Err(err) => eprintln!("accept: {err}"),
        }
    }
}

fn tls_config() -> ServerConfig {
    let provider = Arc::new(ring::default_provider());
    let mut roots = RootCertStore::empty();
    for cert in certs(CA) {
        roots.add(cert).unwrap_or_else(|err| panic!("{CA}: {err}"));
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(KEY).unwrap_or_else(|err| panic!("{KEY}: {err}"));
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(CERT), key)
        .unwrap_or_else(|err| panic!("{CERT}: {err}"))
}

fn certs(path: &str) -> Vec<CertificateDer<'static>> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .unwrap_or_else(|err| panic!("{path}: {err}"))
        .map(|cert| cert.unwrap_or_else(|err| panic!("{path}: {err}")))
        .collect();
    assert!(!certs.is_empty(), "{path}: no certificate");
    certs
}

fn serve(sock: TcpStream, tls: &Arc<ServerConfig>, store: &s3::Store) {
    let peer = sock
        .peer_addr()
        .map_or_else(|err| err.to_string(), |addr| addr.to_string());
    match exchange(sock, tls, store) {
        Ok(200) => {}
        Ok(status) => eprintln!("{peer}: HTTP {status}"),
        Err(err) => eprintln!("{peer}: {err}"),
    }
}

fn exchange(sock: TcpStream, tls: &Arc<ServerConfig>, store: &s3::Store) -> io::Result<u16> {
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.set_write_timeout(Some(TIMEOUT))?;
    let conn = ServerConnection::new(tls.clone()).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, sock);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let host = identity(&stream.conn);
    let status = handle(&mut stream, host.as_deref(), store)?;
    write!(
        stream,
        "HTTP/1.1 {status} \r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(status)
}

// The first DNS name in the verified client certificate names the host in every key it writes.
fn identity(conn: &ServerConnection) -> Option<String> {
    let leaf = conn.peer_certificates()?.first()?;
    let cert = webpki::EndEntityCert::try_from(leaf).ok()?;
    let name = cert.valid_dns_names().next()?.to_ascii_lowercase();
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        .then_some(name)
}

// PUT /<run>/<seq> with a Content-Length body; the status is the answer to send. Requests that can
// be read are read in full before refusing them, so the refusal reaches the client.
fn handle(stream: &mut impl Read, host: Option<&str>, store: &s3::Store) -> io::Result<u16> {
    let mut buf = Vec::with_capacity(MAX_HEAD);
    let mut chunk = [0; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() >= MAX_HEAD {
            return Ok(431);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let Ok(head) = std::str::from_utf8(&buf[..end]) else {
        return Ok(400);
    };
    let mut lines = head.split("\r\n");
    let Some(target) = lines
        .next()
        .and_then(|l| l.strip_prefix("PUT "))
        .and_then(|l| l.strip_suffix(" HTTP/1.1"))
    else {
        return Ok(400);
    };
    let batch = target
        .strip_prefix('/')
        .and_then(|t| t.split_once('/'))
        .and_then(|(run, seq)| Some((run.parse().ok()?, seq.parse().ok()?)));
    let Some(len) = lines.find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    }) else {
        return Ok(411);
    };
    if len > MAX_BODY {
        return Ok(413);
    }
    let mut body = buf.split_off(end);
    let have = body.len().min(len);
    body.resize(len, 0);
    stream.read_exact(&mut body[have..])?;
    let Some(host) = host else {
        return Ok(403);
    };
    let Some((run, seq)) = batch else {
        return Ok(404);
    };
    Ok(store.put(host, run, seq, &body))
}
