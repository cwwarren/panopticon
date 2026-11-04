use std::fs;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use ureq::Agent;
use ureq::http::Uri;
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig, parse_pem};

use crate::decode::{self, Stream};

// The CA that issued the collector's certificate, and this host's client certificate and key.
const CA: &str = "/etc/panopticon/ca.pem";
const CERT: &str = "/etc/panopticon/cert.pem";
const KEY: &str = "/etc/panopticon/key.pem";
// Record bytes waiting for the encoder. Past it the main thread drops whole polls and counts them,
// so it never waits on the network.
const RAW_BYTES: usize = 64 << 20;
const RAW_BATCHES: usize = 4096;
// The collector writes one S3 object per batch, so a batch closes once a minute (about 43,000 PUT
// requests per host per month) or at 8 MiB of gzip, half the collector's limit.
const INTERVAL: Duration = Duration::from_secs(60);
const BATCH_BYTES: usize = 8 << 20;
// Closed batches waiting for the collector: about 1 GB of JSON at 15x compression.
const PENDING_BYTES: usize = 64 << 20;
// Longer than the collector takes to give up on S3, so a slow S3 gets a 503 rather than a retry
// racing the first attempt.
const TIMEOUT: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

pub struct Shipper {
    raw: SyncSender<Vec<u8>>,
    shared: Arc<Shared>,
    encoder: JoinHandle<()>,
    sender: JoinHandle<Stats>,
}

#[derive(Default)]
struct Shared {
    raw_bytes: AtomicUsize,
    pending_bytes: AtomicUsize,
    unreported: AtomicU64,
    lost: AtomicU64,
    stop: AtomicBool,
}

struct Batch {
    seq: u64,
    body: Vec<u8>,
    records: u64,
    reported: u64,
    json: u64,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub records: u64,
    pub batches: u64,
    pub puts: u64,
    pub retries: u64,
    pub lost: u64,
    pub json: u64,
    pub sent: u64,
}

struct Collector {
    agent: Agent,
    base: String,
    run: u64,
}

impl Shipper {
    pub fn new(url: &str) -> Self {
        let collector = Collector::new(url);
        let (raw, queue) = mpsc::sync_channel(RAW_BATCHES);
        let (batches, pending) = mpsc::channel();
        let shared = Arc::new(Shared::default());
        let encoder = {
            let shared = shared.clone();
            thread::spawn(move || encode(&queue, &batches, &shared))
        };
        let sender = {
            let shared = shared.clone();
            thread::spawn(move || send(&collector, &pending, &shared))
        };
        Shipper {
            raw,
            shared,
            encoder,
            sender,
        }
    }

    pub fn push(&self, batch: &[u8]) {
        if self.shared.raw_bytes.load(Relaxed) + batch.len() > RAW_BYTES {
            self.drop_batch(batch);
            return;
        }
        self.shared.raw_bytes.fetch_add(batch.len(), Relaxed);
        match self.raw.try_send(batch.to_vec()) {
            Ok(()) => {}
            Err(TrySendError::Full(batch)) => {
                self.shared.raw_bytes.fetch_sub(batch.len(), Relaxed);
                self.drop_batch(&batch);
            }
            Err(TrySendError::Disconnected(_)) => panic!("shipper exited"),
        }
    }

    fn drop_batch(&self, batch: &[u8]) {
        self.shared.lose(decode::records(batch).count() as u64, 0);
    }

    pub fn finish(self) -> Stats {
        self.shared.stop.store(true, Relaxed);
        drop(self.raw);
        self.encoder.join().unwrap();
        self.sender.join().unwrap()
    }
}

impl Shared {
    // A lost batch's records and the loss count it carried are reported again in a later batch.
    fn lose(&self, records: u64, reported: u64) {
        self.unreported.fetch_add(records + reported, Relaxed);
        self.lost.fetch_add(records, Relaxed);
    }
}

impl Collector {
    fn new(url: &str) -> Self {
        let uri: Uri = url.parse().unwrap_or_else(|err| panic!("{url}: {err}"));
        assert!(
            uri.scheme_str() == Some("https") && uri.path() == "/",
            "{url}: expected https://host:port"
        );
        if let Some((_, port)) = uri.authority().and_then(|a| a.as_str().rsplit_once(':'))
            && !port.ends_with(']')
        {
            assert!(port.parse::<u16>().is_ok(), "{url}: bad port");
        }
        let key = PrivateKey::from_pem(&read(KEY)).unwrap_or_else(|err| panic!("{KEY}: {err}"));
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&certs(CA)))
            .client_cert(Some(ClientCert::new_with_certs(&certs(CERT), key)))
            .build();
        let agent = Agent::config_builder()
            .timeout_connect(Some(TIMEOUT))
            .timeout_per_read(Some(TIMEOUT))
            .timeout_per_write(Some(TIMEOUT))
            .http_status_as_error(false)
            .tls_config(tls)
            .build()
            .new_agent();
        let run = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Collector {
            agent,
            base: url.trim_end_matches('/').to_string(),
            run: u64::try_from(run.as_nanos()).unwrap(),
        }
    }

    fn put(&self, seq: u64, body: &[u8]) -> Result<u16, ureq::Error> {
        let url = format!("{}/{}/{seq}", self.base, self.run);
        Ok(self.agent.put(&url).send(body)?.status().as_u16())
    }
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn certs(path: &str) -> Vec<Certificate<'static>> {
    let certs: Vec<_> = parse_pem(&read(path))
        .filter_map(
            |item| match item.unwrap_or_else(|err| panic!("{path}: {err}")) {
                PemItem::Certificate(cert) => Some(cert),
                _ => None,
            },
        )
        .collect();
    assert!(!certs.is_empty(), "{path}: no certificate");
    certs
}

fn encode(queue: &Receiver<Vec<u8>>, batches: &Sender<Batch>, shared: &Shared) {
    let mut stream = Stream::new();
    let mut lines = Vec::new();
    for seq in 0.. {
        let reported = shared.unreported.swap(0, Relaxed);
        if reported > 0 {
            Stream::loss(&mut lines, reported);
        }
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        let (mut records, mut json) = (0, 0);
        let deadline = Instant::now() + INTERVAL;
        let open = loop {
            gzip.write_all(&lines).unwrap();
            json += lines.len() as u64;
            lines.clear();
            if gzip.get_ref().len() >= BATCH_BYTES {
                break true;
            }
            match queue.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(raw) => {
                    shared.raw_bytes.fetch_sub(raw.len(), Relaxed);
                    records += stream.encode(&raw, &mut lines);
                }
                Err(RecvTimeoutError::Timeout) => break true,
                Err(RecvTimeoutError::Disconnected) => break false,
            }
        };
        let body = gzip.finish().unwrap();
        if shared.pending_bytes.load(Relaxed) + body.len() > PENDING_BYTES {
            shared.lose(records, reported);
        } else {
            shared.pending_bytes.fetch_add(body.len(), Relaxed);
            let batch = Batch {
                seq,
                body,
                records,
                reported,
                json,
            };
            batches.send(batch).unwrap();
        }
        if !open {
            return;
        }
    }
}

fn send(collector: &Collector, pending: &Receiver<Batch>, shared: &Shared) -> Stats {
    let mut stats = Stats::default();
    for batch in pending {
        if deliver(collector, &batch, shared, &mut stats) {
            stats.records += batch.records;
            stats.batches += 1;
            stats.json += batch.json;
            stats.sent += batch.body.len() as u64;
        } else {
            shared.lose(batch.records, batch.reported);
        }
        shared.pending_bytes.fetch_sub(batch.body.len(), Relaxed);
    }
    stats.lost = shared.lost.load(Relaxed);
    stats
}

// Transport errors, 408, 429 and 5xx are retried with doubling backoff until delivered or the agent
// stops; any other status means the collector refused the batch, which is dropped and reported.
fn deliver(collector: &Collector, batch: &Batch, shared: &Shared, stats: &mut Stats) -> bool {
    let mut backoff = Duration::from_secs(1);
    loop {
        stats.puts += 1;
        match collector.put(batch.seq, &batch.body) {
            Ok(status) if (200..300).contains(&status) => return true,
            Ok(status) if status != 408 && status != 429 && status < 500 => {
                eprintln!("collector: HTTP {status}, batch {} dropped", batch.seq);
                return false;
            }
            Ok(status) => eprintln!("collector: HTTP {status}, retrying in {backoff:?}"),
            Err(err) => eprintln!("collector: {err}, retrying in {backoff:?}"),
        }
        if shared.stop.load(Relaxed) {
            return false;
        }
        stats.retries += 1;
        thread::sleep(backoff);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
