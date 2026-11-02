use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::thread;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::wire;

const QUEUE: usize = 1024;
// Distinct executables remembered before the set is cleared; a cleared key costs one idle re-hash.
const SEEN_MAX: usize = 1 << 16;
const CHUNK: usize = 256 << 10;
// The startup backlog sleeps 3x each chunk's hashing time: a quarter of one core at most, so it
// competes less with co-running work through caches and SMT siblings; it finishes about 4x later.
const BACKLOG_PAUSE: u32 = 3;
const IOPRIO_CLASS_IDLE: libc::c_int = 3;
const IOPRIO_CLASS_SHIFT: libc::c_int = 13;
const IOPRIO_WHO_PROCESS: libc::c_int = 1;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Key {
    pub dev: u32,
    pub ino: u64,
    pub ctime: i64,
}

struct Job {
    key: Key,
    pid: Option<u32>,
    path: String,
    jiffies: u64,
}

pub struct Hasher {
    seen: HashSet<Key>,
    backlog: Option<Vec<Job>>,
    jobs: SyncSender<Job>,
    results: Sender<Vec<u8>>,
    done: Receiver<Vec<u8>>,
    pub dropped: u64,
}

impl Hasher {
    pub fn new() -> Self {
        let (jobs, queue) = mpsc::sync_channel::<Job>(QUEUE);
        let (results, done) = mpsc::channel();
        let sender = results.clone();
        thread::spawn(move || work(queue, &sender, 0));
        Hasher {
            seen: HashSet::new(),
            backlog: Some(Vec::new()),
            jobs,
            results,
            done,
            dropped: 0,
        }
    }

    pub fn request(&mut self, key: Key, pid: u32, path: &[u8], jiffies: u64) {
        if key.ino == 0 || self.seen.contains(&key) {
            return;
        }
        if self.seen.len() >= SEEN_MAX {
            self.seen.clear();
        }
        self.seen.insert(key);
        let job = Job {
            key,
            pid: Some(pid),
            path: String::from_utf8_lossy(path).into_owned(),
            jiffies,
        };
        match &mut self.backlog {
            Some(backlog) => backlog.push(job),
            None => {
                if !self.send(job) {
                    self.seen.remove(&key);
                }
            }
        }
    }

    pub fn release_backlog(&mut self) {
        let jobs = self.backlog.take().unwrap();
        let results = self.results.clone();
        thread::spawn(move || work(jobs, &results, BACKLOG_PAUSE));
    }

    pub fn request_file(&mut self, dev: u32, ino: u64, path: &Path, jiffies: u64) {
        let job = Job {
            key: Key { dev, ino, ctime: 0 },
            pid: None,
            path: path.to_string_lossy().into_owned(),
            jiffies,
        };
        self.send(job);
    }

    fn send(&mut self, job: Job) -> bool {
        match self.jobs.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.dropped += 1;
                false
            }
            Err(TrySendError::Disconnected(_)) => panic!("hash worker exited"),
        }
    }

    pub fn collect(&self, buf: &mut Vec<u8>) {
        while let Ok(rec) = self.done.try_recv() {
            buf.extend_from_slice(&rec);
        }
    }
}

fn work(jobs: impl IntoIterator<Item = Job>, results: &Sender<Vec<u8>>, pause: u32) {
    idle();
    let mut chunk = vec![0u8; CHUNK];
    for job in jobs {
        if let Some(rec) = hash(&job, &mut chunk, pause)
            && results.send(rec).is_err()
        {
            return;
        }
    }
}

fn idle() {
    let param = libc::sched_param { sched_priority: 0 };
    assert_eq!(
        unsafe { libc::sched_setscheduler(0, libc::SCHED_IDLE, &param) },
        0,
        "sched_setscheduler: {}",
        io::Error::last_os_error()
    );
    let prio = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, prio) },
        0,
        "ioprio_set: {}",
        io::Error::last_os_error()
    );
}

fn open(job: &Job) -> Option<(File, Key, u64)> {
    let candidates = match job.pid {
        Some(pid) => vec![
            (format!("/proc/{pid}/exe"), 0),
            (job.path.clone(), libc::O_NOFOLLOW),
        ],
        None => vec![(job.path.clone(), libc::O_NOFOLLOW)],
    };
    for (path, nofollow) in candidates {
        let Ok(handle) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | nofollow)
            .open(&path)
        else {
            continue;
        };
        let meta = handle.metadata().unwrap();
        let key = Key {
            dev: wire::kernel_dev(meta.dev()),
            ino: meta.ino(),
            ctime: meta.ctime(),
        };
        if !meta.is_file()
            || key.dev != job.key.dev
            || key.ino != job.key.ino
            || (job.pid.is_some() && key.ctime != job.key.ctime)
        {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", handle.as_raw_fd()))
            .ok()?;
        return Some((file, key, meta.size()));
    }
    None
}

fn hash(job: &Job, chunk: &mut [u8], pause: u32) -> Option<Vec<u8>> {
    let (mut file, key, size) = open(job)?;
    let fd = file.as_raw_fd();
    unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_NOREUSE) };
    let mut digest = Sha256::new();
    let read = loop {
        let start = Instant::now();
        match file.read(chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => digest.update(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => break Err(err),
        }
        if pause > 0 {
            thread::sleep(start.elapsed() * pause);
        }
    };
    unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED) };
    read.ok()?;
    let digest = digest.finalize();
    let mut rec = Vec::new();
    wire::push(
        &mut rec,
        wire::REC_HASH,
        job.jiffies,
        &[
            &key.ino.to_ne_bytes(),
            &key.dev.to_ne_bytes(),
            &[0u8; 4],
            &key.ctime.to_ne_bytes(),
            &size.to_ne_bytes(),
            &digest,
        ],
    );
    Some(rec)
}
