use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;

use sha2::{Digest, Sha256};

use crate::wire;

const QUEUE: usize = 1024;
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
    pid: u32,
    path: String,
    jiffies: u64,
}

pub struct Hasher {
    seen: HashSet<Key>,
    jobs: SyncSender<Job>,
    done: Receiver<Vec<u8>>,
    pub dropped: u64,
}

impl Hasher {
    pub fn new() -> Self {
        let (jobs, queue) = mpsc::sync_channel::<Job>(QUEUE);
        let (results, done) = mpsc::channel();
        thread::spawn(move || {
            idle();
            for job in queue {
                if let Some(rec) = hash(&job) {
                    results.send(rec).unwrap();
                }
            }
        });
        Hasher {
            seen: HashSet::new(),
            jobs,
            done,
            dropped: 0,
        }
    }

    pub fn request(&mut self, key: Key, pid: u32, path: &[u8], jiffies: u64) {
        if key.ino == 0 || !self.seen.insert(key) {
            return;
        }
        let job = Job {
            key,
            pid,
            path: String::from_utf8_lossy(path).into_owned(),
            jiffies,
        };
        match self.jobs.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.seen.remove(&key);
                self.dropped += 1;
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

fn open(job: &Job) -> Option<(File, u64)> {
    for path in [format!("/proc/{}/exe", job.pid), job.path.clone()] {
        let Ok(file) = File::open(&path) else {
            continue;
        };
        let meta = file.metadata().unwrap();
        if wire::kernel_dev(meta.dev()) == job.key.dev
            && meta.ino() == job.key.ino
            && meta.ctime() == job.key.ctime
        {
            return Some((file, meta.size()));
        }
    }
    None
}

fn hash(job: &Job) -> Option<Vec<u8>> {
    let (mut file, size) = open(job)?;
    let fd = file.as_raw_fd();
    unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_NOREUSE) };
    let mut digest = Sha256::new();
    let read = io::copy(&mut file, &mut digest);
    unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED) };
    read.ok()?;
    let digest = digest.finalize();
    let mut rec = Vec::new();
    wire::push(
        &mut rec,
        wire::REC_HASH,
        job.jiffies,
        &[
            &job.key.ino.to_ne_bytes(),
            &job.key.dev.to_ne_bytes(),
            &[0u8; 4],
            &job.key.ctime.to_ne_bytes(),
            &size.to_ne_bytes(),
            &digest,
        ],
    );
    Some(rec)
}
