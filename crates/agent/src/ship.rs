use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::decode::{self, Stream};

// Record bytes waiting for the encoder. Past it the agent drops whole batches and reports them, so
// a slow or absent collector costs memory up to this bound and never stalls the rings.
const QUEUE_BYTES: usize = 64 << 20;
const QUEUE_BATCHES: usize = 4096;
// The OTel Collector accepts request bodies up to 20 MiB by default.
const BODY_BYTES: usize = 4 << 20;
const INTERVAL: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

pub struct Shipper {
    jobs: SyncSender<Vec<u8>>,
    shared: Arc<Shared>,
    worker: JoinHandle<Stats>,
}

#[derive(Default)]
struct Shared {
    queued: AtomicUsize,
    dropped: AtomicU64,
    stop: AtomicBool,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub records: u64,
    pub posts: u64,
    pub retries: u64,
    pub lost: u64,
}

struct Endpoint {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Shipper {
    pub fn new(url: &str) -> Self {
        let endpoint = Endpoint::parse(url);
        let (jobs, queue) = mpsc::sync_channel(QUEUE_BATCHES);
        let shared = Arc::new(Shared::default());
        let worker = {
            let shared = shared.clone();
            thread::spawn(move || ship(&endpoint, &queue, &shared))
        };
        Shipper {
            jobs,
            shared,
            worker,
        }
    }

    pub fn push(&self, batch: &[u8]) {
        if self.shared.queued.load(Relaxed) + batch.len() > QUEUE_BYTES {
            self.drop_batch(batch);
            return;
        }
        self.shared.queued.fetch_add(batch.len(), Relaxed);
        match self.jobs.try_send(batch.to_vec()) {
            Ok(()) => {}
            Err(TrySendError::Full(batch)) => {
                self.shared.queued.fetch_sub(batch.len(), Relaxed);
                self.drop_batch(&batch);
            }
            Err(TrySendError::Disconnected(_)) => panic!("shipper exited"),
        }
    }

    fn drop_batch(&self, batch: &[u8]) {
        let records = decode::records(batch).count() as u64;
        self.shared.dropped.fetch_add(records, Relaxed);
    }

    pub fn finish(self) -> Stats {
        self.shared.stop.store(true, Relaxed);
        drop(self.jobs);
        self.worker.join().unwrap()
    }
}

impl Endpoint {
    fn parse(url: &str) -> Self {
        let rest = url
            .strip_prefix("http://")
            .unwrap_or_else(|| panic!("{url}: only http:// endpoints are supported"));
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rfind(':') {
            Some(i) if !authority[i..].contains(']') => (
                &authority[..i],
                authority[i + 1..]
                    .parse()
                    .unwrap_or_else(|_| panic!("{url}: bad port")),
            ),
            _ => (authority, 80),
        };
        Endpoint {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port,
            authority: authority.to_string(),
            path: if path.is_empty() || path == "/" {
                "/v1/logs".to_string()
            } else {
                path.to_string()
            },
        }
    }

    fn post(&self, body: &[u8]) -> io::Result<u16> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("no address"))?;
        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.authority,
            body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
        let mut response = Vec::new();
        stream.take(1 << 16).read_to_end(&mut response)?;
        response
            .get(9..12)
            .and_then(|code| std::str::from_utf8(code).ok()?.parse().ok())
            .ok_or_else(|| io::Error::other("malformed response"))
    }
}

fn ship(endpoint: &Endpoint, queue: &Receiver<Vec<u8>>, shared: &Shared) -> Stats {
    let mut stream = Stream::new();
    let mut records = Vec::with_capacity(BODY_BYTES);
    let mut body = Vec::with_capacity(BODY_BYTES);
    let mut pending = 0;
    let mut lost = 0;
    let mut stats = Stats::default();
    let mut deadline = Instant::now() + INTERVAL;
    loop {
        let open = match queue.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(batch) => {
                shared.queued.fetch_sub(batch.len(), Relaxed);
                pending += stream.encode(&batch, &mut records, b',');
                true
            }
            Err(RecvTimeoutError::Timeout) => true,
            Err(RecvTimeoutError::Disconnected) => false,
        };
        if open && records.len() < BODY_BYTES && Instant::now() < deadline {
            continue;
        }
        lost += shared.dropped.swap(0, Relaxed);
        if lost > 0 {
            stream.loss(&mut records, lost);
        }
        if !records.is_empty() {
            stream.body(&mut body, &records);
            if deliver(endpoint, &body, shared, &mut stats) {
                stats.records += pending;
                stats.lost += lost;
                lost = 0;
            } else {
                lost += pending;
            }
            records.clear();
            pending = 0;
        }
        deadline = Instant::now() + INTERVAL;
        if !open {
            stats.lost += lost;
            return stats;
        }
    }
}

// Transport errors, 408, 429 and 5xx are retried with doubling backoff until delivered or the agent
// stops; any other status means the collector refused the batch, which is dropped and reported.
fn deliver(endpoint: &Endpoint, body: &[u8], shared: &Shared, stats: &mut Stats) -> bool {
    let mut backoff = Duration::from_secs(1);
    loop {
        stats.posts += 1;
        match endpoint.post(body) {
            Ok(status) if (200..300).contains(&status) => return true,
            Ok(status) if status != 408 && status != 429 && status < 500 => {
                eprintln!("otlp: HTTP {status}, batch dropped");
                return false;
            }
            Ok(status) => eprintln!("otlp: HTTP {status}, retrying in {backoff:?}"),
            Err(err) => eprintln!("otlp: {err}, retrying in {backoff:?}"),
        }
        if shared.stop.load(Relaxed) {
            return false;
        }
        stats.retries += 1;
        thread::sleep(backoff);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}
