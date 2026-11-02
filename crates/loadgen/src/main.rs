use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{self, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use std::{env, ptr, thread};

use io_uring::{IoUring, opcode, squeue, types};

const CANARY: &CStr = c"/etc/pano-canary";
const URING_CANARY: &CStr = c"/etc/pano-canary-uring";
static TARGET: AtomicU64 = AtomicU64::new(0);

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["bench", workload, threads, secs, rest @ ..] => bench(
            workload,
            threads.parse().unwrap(),
            secs.parse().unwrap(),
            rest,
        ),
        ["act", action] => {
            act(action);
            println!("ok {action} pid={}", process::id());
        }
        _ => {
            eprintln!(
                "usage: loadgen bench <getppid|exec|connect|unix|udp|open> <threads> <secs> [path, {{}} = thread index]\n       loadgen act <action>"
            );
            process::exit(2);
        }
    }
}

fn bench(workload: &str, threads: usize, secs: f64, rest: &[&str]) {
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let ops: u64 = thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|i| {
                let stop = &stop;
                s.spawn(move || worker(workload, rest, i, stop))
            })
            .collect();
        thread::sleep(Duration::from_secs_f64(secs));
        stop.store(true, Relaxed);
        workers.into_iter().map(|w| w.join().unwrap()).sum()
    });
    let secs = start.elapsed().as_secs_f64();
    println!(
        r#"{{"workload":"{workload}","threads":{threads},"secs":{secs:.3},"ops":{ops},"ops_per_sec":{:.1}}}"#,
        ops as f64 / secs
    );
}

fn worker(workload: &str, rest: &[&str], index: usize, stop: &AtomicBool) -> u64 {
    let mut ops = 0;
    match workload {
        "getppid" => {
            while !stop.load(Relaxed) {
                for _ in 0..1000 {
                    unsafe { libc::getppid() };
                }
                ops += 1000;
            }
        }
        "exec" => {
            while !stop.load(Relaxed) {
                assert!(Command::new(rest[0]).status().unwrap().success());
                ops += 1;
            }
        }
        "connect" => {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            while !stop.load(Relaxed) {
                let client = TcpStream::connect(addr).unwrap();
                linger0(client.as_raw_fd());
                let (server, _) = listener.accept().unwrap();
                drop(client);
                drop(server);
                ops += 1;
            }
        }
        "unix" => {
            let path = env::temp_dir().join(format!("pano-unix-{}-{index}", process::id()));
            let listener = UnixListener::bind(&path).unwrap();
            while !stop.load(Relaxed) {
                let client = UnixStream::connect(&path).unwrap();
                let (server, _) = listener.accept().unwrap();
                drop(client);
                drop(server);
                ops += 1;
            }
            fs::remove_file(&path).unwrap();
        }
        "udp" => {
            let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
            let dst = sink.local_addr().unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let payload = [0u8; 64];
            while !stop.load(Relaxed) {
                sock.send_to(&payload, dst).unwrap();
                ops += 1;
            }
        }
        "open" => {
            let path = CString::new(rest[0].replace("{}", &index.to_string())).unwrap();
            while !stop.load(Relaxed) {
                let fd = check(
                    unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) }.into(),
                );
                unsafe { libc::close(fd as RawFd) };
                ops += 1;
            }
        }
        "signal" => {
            let pid = unsafe { libc::getpid() };
            let tid = unsafe { libc::gettid() };
            while !stop.load(Relaxed) {
                for _ in 0..1000 {
                    check(unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGURG) });
                }
                ops += 1000;
            }
        }
        _ => panic!("unknown workload {workload}"),
    }
    ops
}

fn act(action: &str) {
    match action {
        "exec" => spawn("/usr/bin/true", &[]),
        "memfd-exec" => memfd_exec(),
        "reparent-exec" => reparent_exec(),
        "setuid-exec" => spawn("/usr/bin/sudo", &["-n", "/usr/bin/true"]),
        "tcp4-connect" => tcp_connect("127.0.0.1:0"),
        "tcp6-connect" => tcp_connect("[::1]:0"),
        "udp4-sendto" => {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.send_to(b"pano", "127.0.0.1:9").unwrap();
        }
        "tcp-listen" => drop(TcpListener::bind("0.0.0.0:0").unwrap()),
        "packet-socket" => {
            let proto = (libc::ETH_P_ALL as u16).to_be() as i32;
            let fd = check(unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) }.into());
            unsafe { libc::close(fd as RawFd) };
        }
        "unix-connect-docker" => drop(UnixStream::connect("/var/run/docker.sock").unwrap()),
        "open-shadow" => drop(File::open("/etc/shadow").unwrap()),
        "file-create" => fs::write(path(CANARY), b"pano\n").unwrap(),
        "file-chmod-suid" => {
            check(unsafe { libc::chmod(CANARY.as_ptr(), 0o4755) }.into());
        }
        "file-chown" => {
            check(unsafe { libc::chown(CANARY.as_ptr(), 65534, 65534) }.into());
        }
        "file-rename" => {
            fs::rename(path(CANARY), "/etc/pano-canary.renamed").unwrap();
            fs::rename("/etc/pano-canary.renamed", path(CANARY)).unwrap();
        }
        "file-hardlink" => {
            fs::hard_link(path(CANARY), "/etc/pano-canary.link").unwrap();
            fs::remove_file("/etc/pano-canary.link").unwrap();
        }
        "file-symlink" => {
            std::os::unix::fs::symlink("/etc/shadow", "/tmp/pano-shadow-link").unwrap();
            fs::remove_file("/tmp/pano-shadow-link").unwrap();
        }
        "file-timestomp" => {
            let epoch = [libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }; 2];
            check(
                unsafe { libc::utimensat(libc::AT_FDCWD, CANARY.as_ptr(), epoch.as_ptr(), 0) }
                    .into(),
            );
        }
        "file-truncate" => {
            check(unsafe { libc::truncate(CANARY.as_ptr(), 0) }.into());
        }
        "file-setxattr" => {
            let value = b"1";
            let ret = unsafe {
                libc::setxattr(
                    CANARY.as_ptr(),
                    c"user.pano".as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            };
            check(ret.into());
        }
        "file-unlink" => fs::remove_file(path(CANARY)).unwrap(),
        "uring-open-shadow" => uring_open_read(c"/etc/shadow"),
        "uring-file-create" => uring_file_create(),
        "uring-connect" => uring_connect(),
        "module-load" => module_load(),
        "sysctl-write" => {
            let p = "/proc/sys/kernel/printk_ratelimit";
            fs::write(p, fs::read(p).unwrap()).unwrap();
        }
        "bpf-prog-load" => bpf_prog_load(),
        "mount-tmpfs" => mount_tmpfs(),
        "unshare-ns" => in_child(|| {
            check(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWUTS) }.into());
        }),
        "setns" => in_child(|| {
            let ns = File::open("/proc/1/ns/uts").unwrap();
            check(unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWUTS) }.into());
        }),
        "setuid" => in_child(|| {
            check(unsafe { libc::setresuid(65534, 65534, 65534) }.into());
        }),
        "capset" => in_child(capset_drop_all),
        "ptrace-attach" => with_victim(|pid| {
            let null = ptr::null_mut::<libc::c_void>();
            check(unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, null, null) });
            check(unsafe { libc::waitpid(pid, ptr::null_mut(), 0) }.into());
            check(unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, null, null) });
        }),
        "proc-mem-write" => with_victim(|pid| {
            let mem = OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{pid}/mem"))
                .unwrap();
            mem.write_all_at(&1u64.to_ne_bytes(), target_addr())
                .unwrap();
        }),
        "process-vm-writev" => with_victim(|pid| {
            let value = 1u64;
            let local = libc::iovec {
                iov_base: ptr::from_ref(&value).cast_mut().cast(),
                iov_len: 8,
            };
            let remote = libc::iovec {
                iov_base: target_addr() as *mut libc::c_void,
                iov_len: 8,
            };
            check(unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) } as i64);
        }),
        "pidfd-getfd" => with_victim(|pid| {
            let pidfd = check(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) });
            let fd = check(unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, 0, 0) });
            unsafe { libc::close(fd as RawFd) };
            unsafe { libc::close(pidfd as RawFd) };
        }),
        "kill" => with_victim(|pid| {
            check(unsafe { libc::kill(pid, libc::SIGTERM) }.into());
        }),
        "mprotect-exec" => {
            let len = 4096;
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            let addr = unsafe { libc::mmap(ptr::null_mut(), len, prot, flags, -1, 0) };
            assert_ne!(addr, libc::MAP_FAILED);
            check(unsafe { libc::mprotect(addr, len, libc::PROT_READ | libc::PROT_EXEC) }.into());
            unsafe { libc::munmap(addr, len) };
        }
        "mmap-exec-file" => {
            let lib = File::open("/usr/lib/x86_64-linux-gnu/libc.so.6").unwrap();
            let prot = libc::PROT_READ | libc::PROT_EXEC;
            let addr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    4096,
                    prot,
                    libc::MAP_PRIVATE,
                    lib.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED);
            unsafe { libc::munmap(addr, 4096) };
        }
        "kexec-attempt" => {
            let ret = unsafe {
                libc::syscall(libc::SYS_kexec_file_load, -1, -1, 0, ptr::null::<u8>(), 0)
            };
            expect_errno(ret, &[libc::EBADF, libc::EPERM]);
        }
        "settime-attempt" => {
            let now = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ret = unsafe { libc::clock_settime(libc::CLOCK_MONOTONIC, &now) };
            expect_errno(ret.into(), &[libc::EINVAL]);
        }
        _ => panic!("unknown action {action}"),
    }
}

fn check(ret: i64) -> i64 {
    assert!(ret >= 0, "{}", Error::last_os_error());
    ret
}

fn expect_errno(ret: i64, allowed: &[i32]) {
    let errno = Error::last_os_error().raw_os_error().unwrap();
    assert!(
        ret < 0 && allowed.contains(&errno),
        "ret={ret} errno={errno}"
    );
}

fn path(p: &CStr) -> &str {
    p.to_str().unwrap()
}

fn target_addr() -> u64 {
    ptr::from_ref(&TARGET) as u64
}

fn linger0(fd: RawFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let len = size_of::<libc::linger>() as libc::socklen_t;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            ptr::from_ref(&linger).cast(),
            len,
        )
    };
    check(ret.into());
}

fn spawn(program: &str, args: &[&str]) {
    assert!(Command::new(program).args(args).status().unwrap().success());
}

fn wait_ok(pid: libc::pid_t) {
    let mut status = 0;
    check(unsafe { libc::waitpid(pid, &mut status, 0) }.into());
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child {pid} status {status:#x}"
    );
}

fn fork() -> libc::pid_t {
    check(unsafe { libc::fork() }.into()) as libc::pid_t
}

fn in_child(f: impl FnOnce()) {
    let pid = fork();
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    wait_ok(pid);
}

fn with_victim(f: impl FnOnce(libc::pid_t)) {
    let pid = fork();
    if pid == 0 {
        loop {
            unsafe { libc::pause() };
        }
    }
    f(pid);
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, ptr::null_mut(), 0);
    }
}

fn tcp_connect(bind: &str) {
    let listener = TcpListener::bind(bind).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    drop((client, server));
}

fn memfd_exec() {
    let image = fs::read("/usr/bin/true").unwrap();
    let fd = check(unsafe { libc::memfd_create(c"pano-memfd".as_ptr(), libc::MFD_EXEC) }.into())
        as RawFd;
    unsafe { File::from_raw_fd(libc::dup(fd)) }
        .write_all(&image)
        .unwrap();
    in_child(|| {
        let argv = [c"pano-memfd".as_ptr(), ptr::null()];
        let envp = [ptr::null::<libc::c_char>()];
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                c"".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            libc::_exit(127);
        }
    });
}

fn reparent_exec() {
    in_child(|| {
        if fork() == 0 {
            thread::sleep(Duration::from_millis(500));
            panic!(
                "{}",
                Command::new("/usr/bin/true").arg("pano-orphan").exec()
            );
        }
    });
    thread::sleep(Duration::from_secs(1));
}

fn uring(ring: &mut IoUring, sqe: squeue::Entry) -> i32 {
    unsafe { ring.submission().push(&sqe).unwrap() };
    ring.submit_and_wait(1).unwrap();
    let res = ring.completion().next().unwrap().result();
    assert!(res >= 0, "io_uring: {}", Error::from_raw_os_error(-res));
    res
}

fn uring_open_read(file: &CStr) {
    let mut ring = IoUring::new(8).unwrap();
    let open = opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), file.as_ptr()).flags(libc::O_RDONLY);
    let fd = uring(&mut ring, open.build());
    let mut buf = [0u8; 64];
    assert!(
        uring(
            &mut ring,
            opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), 64).build()
        ) > 0
    );
    uring(&mut ring, opcode::Close::new(types::Fd(fd)).build());
}

fn uring_file_create() {
    let mut ring = IoUring::new(8).unwrap();
    let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC;
    let open = opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), URING_CANARY.as_ptr())
        .flags(flags)
        .mode(0o644);
    let fd = uring(&mut ring, open.build());
    let data = b"pano\n";
    uring(
        &mut ring,
        opcode::Write::new(types::Fd(fd), data.as_ptr(), data.len() as u32).build(),
    );
    uring(&mut ring, opcode::Close::new(types::Fd(fd)).build());
    uring(
        &mut ring,
        opcode::UnlinkAt::new(types::Fd(libc::AT_FDCWD), URING_CANARY.as_ptr()).build(),
    );
}

fn uring_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
        unreachable!()
    };
    let sa = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let mut ring = IoUring::new(8).unwrap();
    let sock = uring(
        &mut ring,
        opcode::Socket::new(libc::AF_INET, libc::SOCK_STREAM, 0).build(),
    );
    let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    uring(
        &mut ring,
        opcode::Connect::new(types::Fd(sock), ptr::from_ref(&sa).cast(), len).build(),
    );
    let accept = opcode::Accept::new(
        types::Fd(listener.as_raw_fd()),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    let conn = uring(&mut ring, accept.build());
    uring(&mut ring, opcode::Close::new(types::Fd(conn)).build());
    uring(&mut ring, opcode::Close::new(types::Fd(sock)).build());
}

fn module_load() {
    const MODULE_INIT_COMPRESSED_FILE: libc::c_uint = 4;
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let ko = File::open(format!(
        "/lib/modules/{}/kernel/drivers/net/dummy.ko.zst",
        release.trim()
    ))
    .unwrap();
    let params = c"numdummies=0";
    check(unsafe {
        libc::syscall(
            libc::SYS_finit_module,
            ko.as_raw_fd(),
            params.as_ptr(),
            MODULE_INIT_COMPRESSED_FILE,
        )
    });
    check(unsafe { libc::syscall(libc::SYS_delete_module, c"dummy".as_ptr(), libc::O_NONBLOCK) });
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    tail: [u64; 8],
}

fn bpf_prog_load() {
    const BPF_PROG_LOAD: libc::c_long = 5;
    const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    let insns: [u64; 2] = [0xb7, 0x95];
    let mut prog_name = [0u8; 16];
    prog_name[..4].copy_from_slice(b"pano");
    let attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: 2,
        insns: insns.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name,
        tail: [0; 8],
    };
    let size = size_of::<BpfProgLoadAttr>();
    let fd =
        check(unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_LOAD, ptr::from_ref(&attr), size) });
    unsafe { libc::close(fd as RawFd) };
}

fn mount_tmpfs() {
    let dir = c"/tmp/pano-mnt";
    fs::create_dir_all(path(dir)).unwrap();
    check(
        unsafe {
            libc::mount(
                c"pano".as_ptr(),
                dir.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                ptr::null(),
            )
        }
        .into(),
    );
    check(unsafe { libc::umount2(dir.as_ptr(), 0) }.into());
    fs::remove_dir(path(dir)).unwrap();
}

fn capset_drop_all() {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    check(unsafe { libc::syscall(libc::SYS_capset, ptr::from_ref(&header), data.as_ptr()) });
}
