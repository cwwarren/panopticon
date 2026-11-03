use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;
use ureq::Agent;
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig};

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
    pub json: u64,
    pub sent: u64,
}

struct Endpoint {
    agent: Agent,
    url: String,
}

impl Shipper {
    pub fn new(url: &str) -> Self {
        let endpoint = Endpoint::new(url);
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
    fn new(url: &str) -> Self {
        let uri: Uri = url.parse().unwrap_or_else(|err| panic!("{url}: {err}"));
        assert!(
            matches!(uri.scheme_str(), Some("http" | "https")),
            "{url}: expected an http:// or https:// endpoint"
        );
        if let Some((_, port)) = uri.authority().and_then(|a| a.as_str().rsplit_once(':'))
            && !port.ends_with(']')
        {
            assert!(port.parse::<u16>().is_ok(), "{url}: bad port");
        }
        let agent = Agent::config_builder()
            .timeout_connect(Some(TIMEOUT))
            .timeout_per_read(Some(TIMEOUT))
            .timeout_per_write(Some(TIMEOUT))
            .http_status_as_error(false)
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .new_agent();
        Endpoint {
            agent,
            url: if uri.path() == "/" {
                format!("{}/v1/logs", url.trim_end_matches('/'))
            } else {
                url.to_string()
            },
        }
    }

    fn post(&self, body: &[u8]) -> Result<u16, ureq::Error> {
        let response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .send(body)?;
        Ok(response.status().as_u16())
    }
}

fn compress(body: &[u8], mut out: Vec<u8>) -> Vec<u8> {
    out.clear();
    let mut gzip = GzEncoder::new(out, Compression::fast());
    gzip.write_all(body).unwrap();
    gzip.finish().unwrap()
}

fn ship(endpoint: &Endpoint, queue: &Receiver<Vec<u8>>, shared: &Shared) -> Stats {
    let mut stream = Stream::new();
    let mut records = Vec::with_capacity(BODY_BYTES);
    let mut body = Vec::with_capacity(BODY_BYTES);
    let mut gzip = Vec::new();
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
            gzip = compress(&body, gzip);
            if deliver(endpoint, &gzip, shared, &mut stats) {
                stats.records += pending;
                stats.json += body.len() as u64;
                stats.sent += gzip.len() as u64;
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
