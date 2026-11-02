use std::cell::Cell;
use std::env;
use std::ffi::c_void;
use std::hint::black_box;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, RingBufferBuilder};

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/ringbench.skel.rs"));
}

const MAX_CPUS: usize = 32;
const SPSC_SLOTS: usize = 65536;
const EVENT_SIZE: usize = 64;
const CTL_SIZE: usize = 192;
const PERF_PAGES: usize = 1024;
const POLL: Duration = Duration::from_micros(200);

struct Sink {
    events: Cell<u64>,
    checksum: Cell<u64>,
}

impl Sink {
    fn record(&self, data: &[u8]) {
        self.events.set(self.events.get() + 1);
        self.checksum
            .set(self.checksum.get() ^ u64::from_ne_bytes(data[..8].try_into().unwrap()));
    }
}

unsafe extern "C" fn on_perf_sample(ctx: *mut c_void, _cpu: i32, data: *mut c_void, size: u32) {
    let sink = unsafe { &*ctx.cast::<Sink>() };
    sink.record(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size as usize) });
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let [variant, target, workload @ ..] = args.as_slice() else {
        eprintln!("usage: ringbench <variant|none> <kernel function> <loadgen bench args...>");
        std::process::exit(2);
    };
    let program = match variant.as_str() {
        "perf_out_batched" => "perf_out",
        other => other,
    };
    let ncpus = libbpf_rs::num_possible_cpus().unwrap();
    assert!(ncpus <= MAX_CPUS, "{ncpus} CPUs > MAX_CPUS");

    let mut storage = MaybeUninit::uninit();
    let mut open = bpf::RingbenchSkelBuilder::default()
        .open(&mut storage)
        .unwrap();
    for mut prog in open.open_object_mut().progs_mut() {
        let selected = prog.name() == program;
        prog.set_autoload(selected);
        if selected {
            prog.set_attach_target(0, Some(target.clone())).unwrap();
        }
    }
    let skel = open.load().unwrap();

    let inner: Vec<MapHandle> = match program {
        "rb_percpu_out" => (0..ncpus)
            .map(|cpu| {
                let opts = libbpf_sys::bpf_map_create_opts {
                    sz: size_of::<libbpf_sys::bpf_map_create_opts>() as _,
                    ..Default::default()
                };
                let name = format!("rb_cpu{cpu}");
                let rb =
                    MapHandle::create(MapType::RingBuf, Some(name), 0, 0, 4 << 20, &opts).unwrap();
                let fd = rb.as_fd().as_raw_fd() as u32;
                let key = (cpu as u32).to_ne_bytes();
                skel.maps
                    .rb_percpu
                    .update(&key, &fd.to_ne_bytes(), MapFlags::ANY)
                    .unwrap();
                rb
            })
            .collect(),
        _ => Vec::new(),
    };

    let _link = skel
        .object()
        .progs_mut()
        .find(|p| p.name() == program)
        .map(|p| p.attach().unwrap());

    let sink = Sink {
        events: Cell::new(0),
        checksum: Cell::new(0),
    };
    let loadgen = env::current_exe().unwrap().with_file_name("loadgen");
    let mut command = match env::var("PRODUCER_CPUS") {
        Ok(cpus) => {
            let mut taskset = Command::new("taskset");
            taskset.args(["-c", &cpus]).arg(loadgen);
            taskset
        }
        Err(_) => Command::new(loadgen),
    };
    let mut child = command
        .arg("bench")
        .args(workload)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    if let Ok(cpu) = env::var("CONSUMER_CPU") {
        let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
        unsafe { libc::CPU_SET(cpu.parse().unwrap(), &mut set) };
        assert_eq!(
            unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set) },
            0
        );
    }
    let cpu0 = self_cpu_s();

    match program {
        "rb_shared_default" | "rb_shared_out" | "rb_percpu_out" => {
            let mut builder = RingBufferBuilder::new();
            let cb = |data: &[u8]| {
                sink.record(data);
                0
            };
            if inner.is_empty() {
                builder.add(&skel.maps.rb_shared, cb).unwrap();
            }
            for rb in &inner {
                builder.add(rb, cb).unwrap();
            }
            let rb = builder.build().unwrap();
            drain(&mut child, || rb.consume().unwrap());
        }
        "perf_out" => {
            let opts = libbpf_sys::perf_buffer_opts {
                sz: size_of::<libbpf_sys::perf_buffer_opts>() as _,
                sample_period: if variant == "perf_out_batched" {
                    1024
                } else {
                    1
                },
                ..Default::default()
            };
            let ctx = ptr::from_ref(&sink).cast_mut().cast();
            let fd = skel.maps.perf.as_fd().as_raw_fd();
            let pb = unsafe {
                libbpf_sys::perf_buffer__new(
                    fd,
                    PERF_PAGES as _,
                    Some(on_perf_sample),
                    None,
                    ctx,
                    &opts,
                )
            };
            assert!(
                !pb.is_null(),
                "perf_buffer__new: {}",
                std::io::Error::last_os_error()
            );
            drain(&mut child, || {
                assert!(unsafe { libbpf_sys::perf_buffer__consume(pb) } >= 0)
            });
            unsafe { libbpf_sys::perf_buffer__free(pb) };
        }
        "spsc_out" | "spsc_nots" => {
            let ctl = mmap(skel.maps.spsc_ctl.as_fd().as_raw_fd(), MAX_CPUS * CTL_SIZE);
            let data = mmap(
                skel.maps.spsc_data.as_fd().as_raw_fd(),
                MAX_CPUS * SPSC_SLOTS * EVENT_SIZE,
            );
            let mut tails = vec![0u64; ncpus];
            drain(&mut child, || {
                for (cpu, tail) in tails.iter_mut().enumerate() {
                    let head = unsafe { &*ctl.add(cpu * CTL_SIZE).cast::<AtomicU64>() }
                        .load(Ordering::Acquire);
                    while *tail < head {
                        let slot = cpu * SPSC_SLOTS + (*tail as usize & (SPSC_SLOTS - 1));
                        sink.record(unsafe {
                            std::slice::from_raw_parts(data.add(slot * EVENT_SIZE), EVENT_SIZE)
                        });
                        *tail += 1;
                    }
                    unsafe { &*ctl.add(cpu * CTL_SIZE + 64).cast::<AtomicU64>() }
                        .store(*tail, Ordering::Release);
                }
            });
        }
        _ => drain(&mut child, || {}),
    }
    let consumer_cpu_s = self_cpu_s() - cpu0;
    black_box(sink.checksum.get());

    let mut drops: u64 = skel
        .maps
        .drops
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap()
        .unwrap()
        .iter()
        .map(|v| u64::from_ne_bytes(v[..8].try_into().unwrap()))
        .sum();
    if program.starts_with("spsc") {
        let ctl = mmap(skel.maps.spsc_ctl.as_fd().as_raw_fd(), MAX_CPUS * CTL_SIZE);
        drops += (0..ncpus)
            .map(|cpu| unsafe { *ctl.add(cpu * CTL_SIZE + 128).cast::<u64>() })
            .sum::<u64>();
    }
    let output = child.wait_with_output().unwrap();
    println!(
        r#"{{"variant":"{variant}","target":"{target}","result":{},"consumed":{},"drops":{drops},"consumer_cpu_s":{consumer_cpu_s:.3}}}"#,
        String::from_utf8(output.stdout).unwrap().trim(),
        sink.events.get()
    );
}

fn drain(child: &mut Child, mut consume: impl FnMut()) {
    while child.try_wait().unwrap().is_none() {
        consume();
        thread::sleep(POLL);
    }
    consume();
}

fn mmap(fd: RawFd, len: usize) -> *mut u8 {
    let len = len.div_ceil(4096) * 4096;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let addr = unsafe { libc::mmap(ptr::null_mut(), len, prot, libc::MAP_SHARED, fd, 0) };
    assert_ne!(
        addr,
        libc::MAP_FAILED,
        "mmap: {}",
        std::io::Error::last_os_error()
    );
    addr.cast()
}

fn self_cpu_s() -> f64 {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    secs(usage.ru_utime) + secs(usage.ru_stime)
}
