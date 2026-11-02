use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Iter, Link, MapCore, MapFlags, ProgramInput};

use crate::bpf::{AgentSkel, AgentSkelBuilder, types};
use crate::container;
use crate::hash::{self, Hasher};
use crate::wire;

static STOP: AtomicBool = AtomicBool::new(false);

const READ: u32 = libc::IN_OPEN;
const CHANGE: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_MOVE_SELF
    | libc::IN_DELETE_SELF;
const WATCHES: &[(&str, u32)] = &[
    ("/etc/shadow", READ),
    ("/etc/gshadow", READ),
    ("/etc/security/opasswd", READ),
    ("/etc", CHANGE),
    ("/etc/security", CHANGE),
    ("/etc/sudoers.d", CHANGE),
    ("/etc/pam.d", CHANGE),
    ("/etc/ssh", CHANGE),
    ("/etc/ssh/sshd_config.d", CHANGE),
    ("/etc/cron.d", CHANGE),
    ("/etc/cron.hourly", CHANGE),
    ("/etc/cron.daily", CHANGE),
    ("/etc/cron.weekly", CHANGE),
    ("/etc/cron.monthly", CHANGE),
    ("/var/spool/cron", CHANGE),
    ("/var/spool/cron/crontabs", CHANGE),
    ("/var/spool/cron/atjobs", CHANGE),
    ("/etc/systemd/user", CHANGE),
    ("/usr/lib/systemd/system", CHANGE),
    ("/usr/lib/systemd/user", CHANGE),
    ("/etc/init.d", CHANGE),
    ("/etc/profile.d", CHANGE),
    ("/etc/ld.so.conf.d", CHANGE),
    ("/etc/udev/rules.d", CHANGE),
    ("/etc/modprobe.d", CHANGE),
    ("/etc/modules-load.d", CHANGE),
    ("/etc/update-motd.d", CHANGE),
    ("/etc/apt/apt.conf.d", CHANGE),
    ("/etc/xdg/autostart", CHANGE),
    ("/boot", CHANGE),
    ("/usr/bin", CHANGE),
    ("/usr/sbin", CHANGE),
    ("/usr/local/bin", CHANGE),
    ("/usr/local/sbin", CHANGE),
];
const HOME_SECRETS: &[&str] = &[
    ".ssh",
    ".aws",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".gnupg",
];
const HOME_CHANGE: &[&str] = &["", ".config/autostart", ".config/systemd/user"];
const SOCKETS: &[&str] = &[
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/k3s/containerd/containerd.sock",
    "/run/crio/crio.sock",
    "/run/podman/podman.sock",
];
const CLASSES: [&str; 5] = ["proc", "net", "file", "admin", "nat"];

struct Ring {
    class: usize,
    cpu: usize,
    data: *const u8,
    size: u64,
    ctl: *mut types::ctl,
    tail: u64,
    records: u64,
    bytes: u64,
    drops_reported: u64,
}

impl Ring {
    fn drain(&mut self, out: &mut Vec<u8>, hashes: &mut Hasher) {
        let head =
            unsafe { AtomicU64::from_ptr(&raw mut (*self.ctl).head) }.load(Ordering::Acquire);
        while self.tail < head {
            let rec = unsafe { self.data.add((self.tail & (self.size - 1)) as usize) };
            let len = u64::from(unsafe { ptr::read_unaligned(rec.cast::<u16>()) });
            assert!(
                len >= wire::HDR as u64 && len % 8 == 0 && self.tail + len <= head,
                "corrupt ring {}/{} at {}",
                CLASSES[self.class],
                self.cpu,
                self.tail
            );
            let start = out.len();
            out.extend_from_slice(unsafe { std::slice::from_raw_parts(rec, len as usize) });
            let ty = out[start + 2];
            if ty == types::rec_type::REC_CGROUP.0 as u8 {
                let r: types::cgroup_rec = wire::read(&out[start..]);
                let body = &out[start + size_of::<types::cgroup_rec>()..];
                let path = String::from_utf8_lossy(&body[..usize::from(r.path_len)]).into_owned();
                container::push(out, r.h.jiffies, r.id, &path);
            } else if ty == types::rec_type::REC_EXEC.0 as u8 {
                request_hash(hashes, &out[start..]);
            }
            self.tail += len;
            self.records += 1;
            self.bytes += len;
        }
        unsafe { AtomicU64::from_ptr(&raw mut (*self.ctl).tail) }
            .store(self.tail, Ordering::Release);
    }

    fn drops(&self) -> u64 {
        unsafe { AtomicU64::from_ptr(&raw mut (*self.ctl).drops) }.load(Ordering::Relaxed)
    }
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

pub fn run(out_path: &str, poll: Duration) {
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    let ncpus = libbpf_rs::num_possible_cpus().unwrap();
    let nclasses = types::ring_class::NR_CLASSES.0 as usize;
    let mut storage = MaybeUninit::uninit();
    let mut open = AgentSkelBuilder::default().open(&mut storage).unwrap();
    let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
    rodata.nr_cpus = u32::try_from(ncpus).unwrap();
    rodata.agent_tgid = process::id();
    for map in [
        &mut open.maps.ring_proc,
        &mut open.maps.ring_net,
        &mut open.maps.ring_file,
        &mut open.maps.ring_admin,
        &mut open.maps.ring_nat,
    ] {
        map.set_max_entries(u32::try_from(ncpus).unwrap()).unwrap();
    }
    open.maps
        .ctl
        .set_max_entries(u32::try_from(nclasses * ncpus).unwrap())
        .unwrap();
    open.progs.file_flush.set_autoattach(false);
    let mut skel = open.load().unwrap();
    skel.attach().unwrap();
    let flush = skel
        .progs
        .file_flush
        .attach_iter(skel.maps.file_seen.as_fd())
        .unwrap();

    let mut rings = map_rings(&skel, ncpus, nclasses);
    let hz = measure_hz(&skel);
    skel.maps.bss_data.as_deref_mut().unwrap().file_window = hz;
    File::create(out_path).unwrap();
    let mut out = fs::OpenOptions::new().append(true).open(out_path).unwrap();
    let mut buf = Vec::with_capacity(4 << 20);
    buf.extend_from_slice(wire::MAGIC);
    let mut jiffies = push_clock(&skel, &mut buf);
    push_meta(&mut buf, jiffies, ncpus, hz);
    let inotify = watch(&mut buf, jiffies);
    watch_sockets(&skel, &mut buf, jiffies);
    push_cgroups(&mut buf, jiffies, Path::new("/sys/fs/cgroup"), "");
    let mut hashes = Hasher::new();
    push_snapshot(&skel, &mut buf, &mut hashes);
    out.write_all(&buf).unwrap();
    buf.clear();
    eprintln!("ready");

    let mut last_clock = Instant::now();
    let mut coalesced = 0;
    loop {
        let stop = STOP.load(Ordering::Relaxed);
        for ring in &mut rings {
            ring.drain(&mut buf, &mut hashes);
        }
        drain_inotify(inotify);
        hashes.collect(&mut buf);
        if stop || last_clock.elapsed() >= Duration::from_secs(1) {
            jiffies = push_clock(&skel, &mut buf);
            for ring in &mut rings {
                push_loss(ring, &mut buf, jiffies);
            }
            coalesced += push_repeats(&flush, &mut buf);
            eprintln!("{}", stats_line(&rings, nclasses, coalesced));
            last_clock = Instant::now();
        }
        if !buf.is_empty() {
            out.write_all(&buf).unwrap();
            buf.clear();
        }
        if stop {
            break;
        }
        thread::sleep(poll);
    }
    report(&rings, nclasses, coalesced);
    eprintln!("hash: dropped={}", hashes.dropped);
}

fn map_rings(skel: &AgentSkel, ncpus: usize, nclasses: usize) -> Vec<Ring> {
    let ctl = mmap(
        skel.maps.ctl.as_fd().as_raw_fd(),
        nclasses * ncpus * size_of::<types::ctl>(),
    )
    .cast::<types::ctl>();
    let classes = [
        (types::ring_class::CLASS_PROC, &skel.maps.ring_proc),
        (types::ring_class::CLASS_NET, &skel.maps.ring_net),
        (types::ring_class::CLASS_FILE, &skel.maps.ring_file),
        (types::ring_class::CLASS_ADMIN, &skel.maps.ring_admin),
        (types::ring_class::CLASS_NAT, &skel.maps.ring_nat),
    ];
    let mut rings = Vec::new();
    for (class, map) in classes {
        let class = class.0 as usize;
        let value_size = map.value_size() as usize;
        let size = 1u64 << (u64::BITS - 1 - (value_size as u64).leading_zeros());
        let data = mmap(map.as_fd().as_raw_fd(), value_size * ncpus);
        for cpu in 0..ncpus {
            rings.push(Ring {
                class,
                cpu,
                data: unsafe { data.add(cpu * value_size) },
                size,
                ctl: unsafe { ctl.add(class * ncpus + cpu) },
                tail: 0,
                records: 0,
                bytes: 0,
                drops_reported: 0,
            });
        }
    }
    rings
}

fn mmap(fd: RawFd, len: usize) -> *mut u8 {
    let len = len.div_ceil(4096) * 4096;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let addr = unsafe { libc::mmap(ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, 0) };
    assert_ne!(
        addr,
        libc::MAP_FAILED,
        "mmap: {}",
        io::Error::last_os_error()
    );
    addr.cast()
}

fn read_jiffies(skel: &AgentSkel) -> u64 {
    let run = skel
        .progs
        .clock_now
        .test_run(ProgramInput::default())
        .unwrap();
    assert_eq!(run.return_value, 0);
    let bss = skel.maps.bss_data.as_deref().unwrap();
    unsafe { ptr::read_volatile(&bss.clock_jiffies) }
}

fn measure_hz(skel: &AgentSkel) -> u64 {
    let start = (read_jiffies(skel), Instant::now());
    thread::sleep(Duration::from_millis(200));
    let ticks = read_jiffies(skel) - start.0;
    let hz = (ticks as f64 / start.1.elapsed().as_secs_f64()).round() as u64;
    *[100u64, 250, 300, 1000]
        .iter()
        .min_by_key(|&&c| c.abs_diff(hz))
        .unwrap()
}

fn push_clock(skel: &AgentSkel, buf: &mut Vec<u8>) -> u64 {
    let jiffies = read_jiffies(skel);
    let realtime = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) },
        0
    );
    let boottime =
        u64::try_from(ts.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap();
    wire::push(
        buf,
        wire::REC_CLOCK,
        jiffies,
        &[
            &jiffies.to_ne_bytes(),
            &realtime.to_ne_bytes(),
            &boottime.to_ne_bytes(),
        ],
    );
    jiffies
}

fn push_meta(buf: &mut Vec<u8>, jiffies: u64, ncpus: usize, hz: u64) {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let (boot_id, host) = (boot_id.trim().as_bytes(), host.trim().as_bytes());
    wire::push(
        buf,
        wire::REC_META,
        jiffies,
        &[
            &u32::try_from(ncpus).unwrap().to_ne_bytes(),
            &u32::try_from(hz).unwrap().to_ne_bytes(),
            &u16::try_from(boot_id.len()).unwrap().to_ne_bytes(),
            &u16::try_from(host.len()).unwrap().to_ne_bytes(),
            &[0u8; 4],
            boot_id,
            host,
        ],
    );
}

fn entries(dir: &str) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => panic!("read_dir {dir}: {err}"),
    }
}

fn subdirs(dir: &str) -> Vec<PathBuf> {
    entries(dir).into_iter().filter(|p| p.is_dir()).collect()
}

fn watch_list() -> Vec<(PathBuf, u32)> {
    let mut list: Vec<(PathBuf, u32)> = WATCHES
        .iter()
        .map(|&(p, m)| (PathBuf::from(p), m))
        .collect();
    let mut homes = subdirs("/home");
    homes.push(PathBuf::from("/root"));
    for home in homes {
        list.extend(HOME_SECRETS.iter().map(|d| (home.join(d), READ | CHANGE)));
        list.extend(HOME_CHANGE.iter().map(|d| (home.join(d), CHANGE)));
    }
    list.push((PathBuf::from("/etc/systemd/system"), CHANGE));
    list.extend(
        subdirs("/etc/systemd/system")
            .into_iter()
            .map(|d| (d, CHANGE)),
    );
    for lib in subdirs("/usr/lib") {
        if lib.to_string_lossy().ends_with("-linux-gnu") {
            list.push((lib.join("security"), CHANGE));
            list.push((lib, CHANGE));
        }
    }
    list.extend(
        entries("/etc/ssh")
            .into_iter()
            .filter(|p| {
                let name = p.file_name().unwrap().to_string_lossy();
                name.starts_with("ssh_host_") && name.ends_with("_key")
            })
            .map(|p| (p, READ)),
    );
    list
}

fn watch(buf: &mut Vec<u8>, jiffies: u64) -> RawFd {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(fd >= 0, "inotify_init1: {}", io::Error::last_os_error());
    for (path, mask) in watch_list() {
        let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
        if unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), mask | libc::IN_MASK_ADD) } < 0 {
            let err = io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ENOENT),
                "inotify_add_watch {path:?}: {err}"
            );
            continue;
        }
        let meta = fs::metadata(&path).unwrap();
        wire::push(
            buf,
            wire::REC_WATCH,
            jiffies,
            &[
                &wire::kernel_dev(meta.dev()).to_ne_bytes(),
                &mask.to_ne_bytes(),
                &meta.ino().to_ne_bytes(),
                path.as_os_str().as_bytes(),
            ],
        );
    }
    fd
}

fn watch_sockets(skel: &AgentSkel, buf: &mut Vec<u8>, jiffies: u64) {
    for path in SOCKETS {
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => panic!("stat {path}: {err}"),
        };
        let dev = wire::kernel_dev(meta.dev()).to_ne_bytes();
        let key = [&meta.ino().to_ne_bytes()[..], &dev, &[0u8; 4]].concat();
        skel.maps
            .unix_watch
            .update(&key, &[1], MapFlags::ANY)
            .unwrap();
        wire::push(
            buf,
            wire::REC_WATCH,
            jiffies,
            &[
                &dev,
                &0u32.to_ne_bytes(),
                &meta.ino().to_ne_bytes(),
                path.as_bytes(),
            ],
        );
    }
}

fn request_hash(hashes: &mut Hasher, rec: &[u8]) {
    let r: types::exec_rec = wire::read(rec);
    let path = &rec[size_of::<types::exec_rec>()..][..usize::from(r.path_len)];
    let key = hash::Key {
        dev: r.exe_dev,
        ino: r.exe_ino,
        ctime: r.exe_ctime,
    };
    hashes.request(key, r.pid, path, r.h.jiffies);
}

fn push_snapshot(skel: &AgentSkel, buf: &mut Vec<u8>, hashes: &mut Hasher) {
    let mut raw = Vec::new();
    Iter::new(skel.links.snapshot.as_ref().unwrap())
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    let fixed = size_of::<types::exec_rec>();
    let mut off = 0;
    let mut cwds = HashSet::new();
    while off < raw.len() {
        let mut r: types::exec_rec = wire::read(&raw[off..]);
        let argv = &raw[off + fixed..off + fixed + usize::from(r.argv_len)];
        let path = match fs::read_link(format!("/proc/{}/exe", r.pid)) {
            Ok(path) => path.into_os_string().into_vec(),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => panic!("readlink /proc/{}/exe: {err}", r.pid),
        };
        let path = &path[..path.len().min(types::limits::PATH_MAX_REC.0 as usize)];
        let len = (fixed + path.len() + argv.len()).next_multiple_of(8);
        off += usize::from(r.h.len);
        r.path_len = u16::try_from(path.len()).unwrap();
        r.h.len = u16::try_from(len).unwrap();
        let start = buf.len();
        buf.extend_from_slice(wire::bytes_of(&r));
        buf.extend_from_slice(path);
        buf.extend_from_slice(argv);
        buf.resize(buf.len() + len - fixed - path.len() - argv.len(), 0);
        request_hash(hashes, &buf[start..]);
        if r.cwd_ino != 0 && cwds.insert((r.cwd_dev, r.cwd_ino)) {
            push_cwd(buf, &r);
        }
    }
}

fn push_cwd(buf: &mut Vec<u8>, r: &types::exec_rec) {
    let cwd = match fs::read_link(format!("/proc/{}/cwd", r.pid)) {
        Ok(cwd) => cwd.into_os_string().into_vec(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return,
        Err(err) => panic!("readlink /proc/{}/cwd: {err}", r.pid),
    };
    wire::push(
        buf,
        types::rec_type::REC_PATH.0 as u8,
        r.h.jiffies,
        &[
            &r.cwd_ino.to_ne_bytes(),
            &r.cwd_dev.to_ne_bytes(),
            &u16::try_from(cwd.len()).unwrap().to_ne_bytes(),
            &[0u8; 2],
            &cwd,
        ],
    );
}

fn drain_inotify(fd: RawFd) {
    let mut scratch = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, scratch.as_mut_ptr().cast(), scratch.len()) };
        if n > 0 {
            continue;
        }
        let err = io::Error::last_os_error();
        assert!(
            n < 0 && err.kind() == io::ErrorKind::WouldBlock,
            "inotify read: {err}"
        );
        return;
    }
}

fn push_cgroups(buf: &mut Vec<u8>, jiffies: u64, dir: &Path, rel: &str) {
    let meta = match fs::metadata(dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return,
        Err(err) => panic!("stat {dir:?}: {err}"),
    };
    let path = if rel.is_empty() { "/" } else { rel };
    let len = u16::try_from(path.len()).unwrap();
    wire::push(
        buf,
        types::rec_type::REC_CGROUP.0 as u8,
        jiffies,
        &[
            &meta.ino().to_ne_bytes(),
            &len.to_ne_bytes(),
            &[0u8; 6],
            path.as_bytes(),
        ],
    );
    container::push(buf, jiffies, meta.ino(), path);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return,
        Err(err) => panic!("read_dir {dir:?}: {err}"),
    };
    for entry in entries {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            let child = format!("{rel}/{}", entry.file_name().to_string_lossy());
            push_cgroups(buf, jiffies, &entry.path(), &child);
        }
    }
}

fn push_loss(ring: &mut Ring, buf: &mut Vec<u8>, jiffies: u64) {
    let drops = ring.drops();
    if drops != ring.drops_reported {
        let (class, cpu) = (
            u32::try_from(ring.class).unwrap(),
            u32::try_from(ring.cpu).unwrap(),
        );
        wire::push(
            buf,
            wire::REC_LOSS,
            jiffies,
            &[
                &class.to_ne_bytes(),
                &cpu.to_ne_bytes(),
                &drops.to_ne_bytes(),
            ],
        );
        ring.drops_reported = drops;
    }
}

fn push_repeats(flush: &Link, buf: &mut Vec<u8>) -> u64 {
    let start = buf.len();
    Iter::new(flush).unwrap().read_to_end(buf).unwrap();
    buf[start..]
        .as_chunks::<{ size_of::<types::file_repeat_rec>() }>()
        .0
        .iter()
        .map(|r| wire::read::<types::file_repeat_rec>(r).count)
        .sum()
}

fn stats_line(rings: &[Ring], nclasses: usize, coalesced: u64) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let mut line = format!("stats {ms}");
    for class in 0..nclasses {
        let records: u64 = rings
            .iter()
            .filter(|r| r.class == class)
            .map(|r| r.records)
            .sum();
        line.push_str(&format!(" {records}"));
    }
    let drops: u64 = rings.iter().map(Ring::drops).sum();
    line.push_str(&format!(" {drops} {coalesced}"));
    line
}

fn report(rings: &[Ring], nclasses: usize, coalesced: u64) {
    for (class, name) in CLASSES.iter().enumerate().take(nclasses) {
        let rings = rings.iter().filter(|r| r.class == class);
        let (records, bytes, drops) = rings.fold((0, 0, 0), |(n, b, d), r| {
            (n + r.records, b + r.bytes, d + r.drops())
        });
        eprintln!("{name}: records={records} bytes={bytes} drops={drops}");
    }
    eprintln!("file: coalesced={coalesced}");
}
