use std::collections::HashMap;
use std::fmt::{Display, Write as _};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bpf::types;
use crate::container;
use crate::wire::{self, read};

const EXEC: u32 = types::rec_type::REC_EXEC.0;
const CGROUP: u32 = types::rec_type::REC_CGROUP.0;
const CONNECT: u32 = types::rec_type::REC_CONNECT.0;
const ACCEPT: u32 = types::rec_type::REC_ACCEPT.0;
const LISTEN: u32 = types::rec_type::REC_LISTEN.0;
const BIND: u32 = types::rec_type::REC_BIND.0;
const UDP_SEND: u32 = types::rec_type::REC_UDP_SEND.0;
const DNS_QUERY: u32 = types::rec_type::REC_DNS_QUERY.0;
const DNS_ANSWER: u32 = types::rec_type::REC_DNS_ANSWER.0;
const FILE: u32 = types::rec_type::REC_FILE.0;
const FILE_REPEAT: u32 = types::rec_type::REC_FILE_REPEAT.0;
const EXIT: u32 = types::rec_type::REC_EXIT.0;
const LOGIN: u32 = types::rec_type::REC_LOGIN.0;
const ADMIN: u32 = types::rec_type::REC_ADMIN.0;
const RAW_SOCKET: u32 = types::rec_type::REC_RAW_SOCKET.0;
const UNIX_CONNECT: u32 = types::rec_type::REC_UNIX_CONNECT.0;
const NAT: u32 = types::rec_type::REC_NAT.0;
const PATH: u32 = types::rec_type::REC_PATH.0;
const META: u32 = wire::REC_META as u32;
const CLOCK: u32 = wire::REC_CLOCK as u32;
const LOSS: u32 = wire::REC_LOSS as u32;
const WATCH: u32 = wire::REC_WATCH as u32;
const CONTAINER: u32 = wire::REC_CONTAINER as u32;
const HASH: u32 = wire::REC_HASH as u32;
const MISS: u32 = wire::REC_MISS as u32;

const MASKS: [(u32, &str); 15] = [
    (0x1, "access"),
    (0x2, "modify"),
    (0x4, "attrib"),
    (0x8, "close_write"),
    (0x10, "close_nowrite"),
    (0x20, "open"),
    (0x40, "moved_from"),
    (0x80, "moved_to"),
    (0x100, "create"),
    (0x200, "delete"),
    (0x400, "delete_self"),
    (0x800, "move_self"),
    (0x2000, "unmount"),
    (0x0800_0000, "on_child"),
    (0x4000_0000, "dir"),
];

type FileKey = (u64, u64, u64, u64, u32, u32);

fn file_key(k: &types::file_key) -> FileKey {
    (k.proc, k.seq, k.ino, k.child_ino, k.dev, k.mask)
}

pub fn decode(path: &str) {
    let data = fs::read(path).unwrap();
    assert_eq!(&data[..8], wire::MAGIC, "not a panopticon stream");
    let mut decoder = Decoder::default();
    for (rec, h) in records(&data) {
        decoder.index(rec, &h);
    }
    decoder.clocks.sort_unstable();
    for hashes in decoder.inode_hashes.values_mut() {
        hashes.sort_unstable();
    }
    let mut out = BufWriter::new(io::stdout().lock());
    for (rec, h) in records(&data) {
        if let Some(line) = decoder.record(rec, &h) {
            writeln!(out, "{line}").unwrap();
        }
    }
    out.flush().unwrap();
}

fn records(data: &[u8]) -> impl Iterator<Item = (&[u8], types::rec_hdr)> {
    let mut off = 8;
    std::iter::from_fn(move || {
        if off + wire::HDR > data.len() {
            return None;
        }
        let h: types::rec_hdr = read(&data[off..]);
        let len = usize::from(h.len);
        assert!(
            len >= wire::HDR && off + len <= data.len(),
            "truncated record at offset {off}"
        );
        off += len;
        Some((&data[off - len..off], h))
    })
}

#[derive(Default)]
struct Decoder {
    clocks: Vec<(u64, u64)>,
    boot_to_real_ms: i128,
    hz: u64,
    images: HashMap<(u64, u64), String>,
    watches: HashMap<(u32, u64), String>,
    files: HashMap<FileKey, (types::actor, String)>,
    containers: HashMap<u64, String>,
    hashes: HashMap<(u32, u64, i64), String>,
    paths: HashMap<(u32, u64), String>,
    inode_hashes: HashMap<(u32, u64), Vec<(u64, String)>>,
}

struct Obj(String);

impl Obj {
    fn new(kind: &str, ts: u64) -> Self {
        Obj(format!(r#"{{"type":"{kind}","ts":{ts}"#))
    }

    fn num(mut self, key: &str, value: impl Display) -> Self {
        write!(self.0, r#","{key}":{value}"#).unwrap();
        self
    }

    fn str(mut self, key: &str, value: &str) -> Self {
        write!(self.0, r#","{key}":{}"#, quote(value)).unwrap();
        self
    }

    fn raw(mut self, key: &str, json: &str) -> Self {
        write!(self.0, r#","{key}":{json}"#).unwrap();
        self
    }

    fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

fn quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        match c {
            '"' => q.push_str("\\\""),
            '\\' => q.push_str("\\\\"),
            c if (c as u32) < 0x20 => write!(q, "\\u{:04x}", c as u32).unwrap(),
            c => q.push(c),
        }
    }
    q.push('"');
    q
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn sysctl_value(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end >= 2
        && raw[..end]
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return text(&raw[..end]);
    }
    match raw.len() {
        1 => raw[0].to_string(),
        n if n % 4 == 0 => raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| i32::from_ne_bytes(*c).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        _ => raw.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

fn dev(d: u32) -> String {
    format!("{}:{}", d >> 20, d & 0xfffff)
}

const FS_MAGIC: [(u32, &str); 12] = [
    (0x0102_1994, "tmpfs"),
    (0x8584_58f6, "ramfs"),
    (0x9584_58f6, "hugetlbfs"),
    (0x794c_7630, "overlay"),
    (0xef53, "ext4"),
    (0x9123_683e, "btrfs"),
    (0x5846_5342, "xfs"),
    (0x7371_7368, "squashfs"),
    (0x6969, "nfs"),
    (0x6573_5546, "fuse"),
    (0x2fc1_2fc1, "zfs"),
    (0x0102_1997, "9p"),
];

fn fs_name(magic: u32) -> String {
    match FS_MAGIC.iter().find(|(m, _)| *m == magic) {
        Some((_, name)) => (*name).to_string(),
        None => format!("{magic:#x}"),
    }
}

fn fstype(a: u64, b: u64) -> String {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_ne_bytes());
    bytes[8..].copy_from_slice(&b.to_ne_bytes());
    text(&bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(16)])
}

const NAMESPACES: [(u64, &str); 8] = [
    (0x80, "time"),
    (0x2_0000, "mnt"),
    (0x0200_0000, "cgroup"),
    (0x0400_0000, "uts"),
    (0x0800_0000, "ipc"),
    (0x1000_0000, "user"),
    (0x2000_0000, "pid"),
    (0x4000_0000, "net"),
];

fn path_text(raw: &[u8]) -> String {
    let s = text(raw);
    if s.starts_with('/') {
        return s;
    }
    let mut parts: Vec<&str> = s.split('\0').filter(|p| !p.is_empty()).collect();
    parts.reverse();
    format!("/{}", parts.join("/"))
}

fn hash_rec(rec: &[u8]) -> ((u32, u64, i64), u64, String) {
    let (ino, dev_id, ctime, size): (u64, u32, i64, u64) = (
        read(&rec[wire::HDR..]),
        read(&rec[wire::HDR + 8..]),
        read(&rec[wire::HDR + 16..]),
        read(&rec[wire::HDR + 24..]),
    );
    let digest: String = rec[wire::HDR + 32..wire::HDR + 64]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ((dev_id, ino, ctime), size, digest)
}

fn container_json(rec: &[u8]) -> (u64, String) {
    let (cgroup, flags): (u64, u8) = (read(&rec[wire::HDR..]), rec[wire::HDR + 8]);
    let text = String::from_utf8_lossy(&rec[wire::HDR + 16..]);
    let mut parts = text.split('\0');
    let mut field = || quote(parts.next().unwrap_or_default());
    let (runtime, id, name, image, pod, namespace) =
        (field(), field(), field(), field(), field(), field());
    let bit = |b: u8| flags & b != 0;
    let json = format!(
        r#"{{"runtime":{runtime},"id":{id},"name":{name},"image":{image},"pod":{pod},"namespace":{namespace},"privileged":{},"host_pid":{},"host_net":{},"sandbox":{}}}"#,
        bit(container::PRIVILEGED),
        bit(container::HOST_PID),
        bit(container::HOST_NET),
        bit(container::SANDBOX)
    );
    (cgroup, json)
}

fn ns_names(flags: u64) -> String {
    let names: Vec<String> = NAMESPACES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| quote(n))
        .collect();
    format!("[{}]", names.join(","))
}

fn addr(family: u8, raw: &[u8; 16], port: u16) -> String {
    if family == 10 {
        format!("[{}]:{port}", Ipv6Addr::from(*raw))
    } else {
        format!("{}:{port}", Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    }
}

impl Decoder {
    fn index(&mut self, rec: &[u8], h: &types::rec_hdr) {
        match u32::from(h.r#type) {
            CLOCK => {
                let (jiffies, realtime, boottime): (u64, u64, u64) = (
                    read(&rec[wire::HDR..]),
                    read(&rec[wire::HDR + 8..]),
                    read(&rec[wire::HDR + 16..]),
                );
                self.clocks.push((jiffies, realtime / 1_000_000));
                self.boot_to_real_ms =
                    i128::from(realtime / 1_000_000) - i128::from(boottime / 1_000_000);
            }
            META => self.hz = u64::from(read::<u32>(&rec[wire::HDR + 4..])),
            PATH => {
                let r: types::path_rec = read(rec);
                let raw = &rec[size_of::<types::path_rec>()..][..usize::from(r.len)];
                self.paths.insert((r.dev, r.ino), path_text(raw));
            }
            HASH => {
                let (key, _, digest) = hash_rec(rec);
                self.inode_hashes
                    .entry((key.0, key.1))
                    .or_default()
                    .push((h.jiffies, digest.clone()));
                self.hashes.insert(key, digest);
            }
            CONTAINER => {
                let (cgroup, json) = container_json(rec);
                self.containers.insert(cgroup, json);
            }
            WATCH => {
                let (d, ino): (u32, u64) = (read(&rec[wire::HDR..]), read(&rec[wire::HDR + 8..]));
                self.watches.insert(
                    (d, ino),
                    text(&rec[wire::HDR + 16..])
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            EXEC => {
                let r: types::exec_rec = read(rec);
                let path = text(&rec[size_of::<types::exec_rec>()..][..usize::from(r.path_len)]);
                self.images.insert((r.proc, r.exec_seq), path);
            }
            FILE => {
                let r: types::file_rec = read(rec);
                let name = text(&rec[size_of::<types::file_rec>()..][..usize::from(r.name_len)]);
                self.files.entry(file_key(&r.k)).or_insert((r.a, name));
            }
            _ => {}
        }
    }

    fn ts(&self, jiffies: u64) -> u64 {
        let i = self.clocks.partition_point(|&(j, _)| j <= jiffies).max(1) - 1;
        let (clock_jiffies, clock_ms) = self.clocks[i];
        let delta = jiffies as i128 - clock_jiffies as i128;
        (clock_ms as i128 + delta * 1000 / self.hz.max(1) as i128) as u64
    }

    fn exe(&self, a: &types::actor) -> String {
        self.images
            .get(&(a.image_proc, a.image_seq))
            .cloned()
            .unwrap_or_default()
    }

    fn actor(&self, obj: Obj, a: &types::actor) -> Obj {
        obj.num("proc", a.proc)
            .str("image", &format!("{}:{}", a.image_proc, a.image_seq))
            .str("exe", &self.exe(a))
            .num("cgroup", a.cgroup)
            .raw(
                "container",
                self.containers
                    .get(&a.cgroup)
                    .map_or("null", String::as_str),
            )
            .num("pid", a.pid)
            .num("tid", a.tid)
    }

    fn file(&self, obj: Obj, k: &types::file_key) -> Obj {
        let mask: Vec<String> = MASKS
            .iter()
            .filter(|(bit, _)| k.mask & bit != 0)
            .map(|(_, n)| quote(n))
            .collect();
        obj.str(
            "path",
            &self
                .watches
                .get(&(k.dev, k.ino))
                .cloned()
                .unwrap_or_default(),
        )
        .str("dev", &dev(k.dev))
        .num("ino", k.ino)
        .num("child_ino", k.child_ino)
        .raw("mask", &format!("[{}]", mask.join(",")))
    }

    fn record(&self, rec: &[u8], h: &types::rec_hdr) -> Option<String> {
        let ts = self.ts(h.jiffies);
        let line = match u32::from(h.r#type) {
            CLOCK => return None,
            META => {
                let (ncpus, hz): (u32, u32) =
                    (read(&rec[wire::HDR..]), read(&rec[wire::HDR + 4..]));
                let (boot_len, host_len): (u16, u16) =
                    (read(&rec[wire::HDR + 8..]), read(&rec[wire::HDR + 10..]));
                let body = &rec[wire::HDR + 16..];
                Obj::new("meta", ts)
                    .num("ncpus", ncpus)
                    .num("hz", hz)
                    .str("boot_id", &text(&body[..usize::from(boot_len)]))
                    .str(
                        "host",
                        &text(
                            &body[usize::from(boot_len)
                                ..usize::from(boot_len) + usize::from(host_len)],
                        ),
                    )
            }
            PATH => {
                let r: types::path_rec = read(rec);
                let raw = &rec[size_of::<types::path_rec>()..][..usize::from(r.len)];
                Obj::new("path", ts)
                    .str("dev", &dev(r.dev))
                    .num("ino", r.ino)
                    .str("path", &path_text(raw))
            }
            HASH => {
                let ((dev_id, ino, ctime), size, digest) = hash_rec(rec);
                Obj::new("hash", ts)
                    .str("dev", &dev(dev_id))
                    .num("ino", ino)
                    .num("ctime", ctime)
                    .num("size", size)
                    .str("sha256", &digest)
            }
            CONTAINER => {
                let (cgroup, json) = container_json(rec);
                Obj::new("container", ts)
                    .num("cgroup", cgroup)
                    .raw("container", &json)
            }
            WATCH => {
                let (d, mask, ino): (u32, u32, u64) = (
                    read(&rec[wire::HDR..]),
                    read(&rec[wire::HDR + 4..]),
                    read(&rec[wire::HDR + 8..]),
                );
                let path = text(&rec[wire::HDR + 16..])
                    .trim_end_matches('\0')
                    .to_string();
                Obj::new("watch", ts)
                    .str("path", &path)
                    .str("dev", &dev(d))
                    .num("ino", ino)
                    .num("mask", mask)
            }
            LOSS => {
                let (class, cpu, drops): (u32, u32, u64) = (
                    read(&rec[wire::HDR..]),
                    read(&rec[wire::HDR + 4..]),
                    read(&rec[wire::HDR + 8..]),
                );
                Obj::new("loss", ts)
                    .num("class", class)
                    .num("cpu", cpu)
                    .num("drops", drops)
            }
            MISS => {
                let count: u64 = read(&rec[wire::HDR..]);
                let name = &rec[wire::HDR + 8..];
                let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                Obj::new("miss", ts)
                    .str("prog", &text(name))
                    .num("count", count)
            }
            EXEC => self.exec(rec, h, ts),
            CGROUP => {
                let r: types::cgroup_rec = read(rec);
                let body = &rec[size_of::<types::cgroup_rec>()..];
                Obj::new("cgroup", ts)
                    .num("id", r.id)
                    .str("path", &text(&body[..usize::from(r.path_len)]))
            }
            CONNECT | ACCEPT | LISTEN | BIND | UDP_SEND | DNS_QUERY | DNS_ANSWER => {
                self.sock(rec, h, ts)
            }
            FILE => {
                let r: types::file_rec = read(rec);
                let name = text(&rec[size_of::<types::file_rec>()..][..usize::from(r.name_len)]);
                let changed = r.k.mask & (0x8 | 0x80) != 0;
                let sha256 = self
                    .inode_hashes
                    .get(&(r.k.dev, r.k.child_ino))
                    .and_then(|v| v.iter().find(|(j, _)| changed && *j >= h.jiffies))
                    .map_or("", |(_, d)| d.as_str());
                self.file(
                    self.actor(Obj::new("file", ts), &r.a).str("name", &name),
                    &r.k,
                )
                .str("sha256", sha256)
            }
            FILE_REPEAT => {
                let r: types::file_repeat_rec = read(rec);
                let obj = Obj::new("file_repeat", ts).num("count", r.count);
                let obj = match self.files.get(&file_key(&r.k)) {
                    Some((a, name)) => self.actor(obj, a).str("name", name),
                    None => obj.num("proc", r.k.proc),
                };
                self.file(obj, &r.k)
            }
            EXIT => {
                let r: types::exit_rec = read(rec);
                let code = r.exit_code;
                let obj = self
                    .actor(Obj::new("exit", ts), &r.a)
                    .num(
                        "start",
                        i128::from(r.start_boottime / 1_000_000) + self.boot_to_real_ms,
                    )
                    .num("cpu_ms", r.cpu_ns / 1_000_000);
                if code & 0x7f != 0 {
                    obj.num("signal", code & 0x7f).num("core", code & 0x80 != 0)
                } else {
                    obj.num("status", (code >> 8) & 0xff)
                }
            }
            LOGIN => {
                let r: types::login_rec = read(rec);
                self.actor(Obj::new("login", ts), &r.a)
                    .num("loginuid", r.loginuid)
                    .num("sessionid", r.sessionid)
            }
            ADMIN => self.admin(rec, ts),
            RAW_SOCKET => {
                let r: types::raw_rec = read(rec);
                let family = match r.family {
                    2 => "inet",
                    10 => "inet6",
                    17 => "packet",
                    _ => "other",
                };
                self.actor(Obj::new("raw_socket", ts), &r.a)
                    .str("family", family)
                    .num("sock_type", r.r#type)
                    .str("protocol", &format!("{:#x}", r.protocol))
                    .num("netns", r.netns)
            }
            UNIX_CONNECT => {
                let r: types::unix_rec = read(rec);
                let path = self
                    .watches
                    .get(&(r.dev, r.ino))
                    .cloned()
                    .unwrap_or_default();
                self.actor(Obj::new("unix_connect", ts), &r.a)
                    .str("path", &path)
                    .str("dev", &dev(r.dev))
                    .num("ino", r.ino)
            }
            NAT => {
                let r: types::nat_rec = read(rec);
                Obj::new("nat", ts)
                    .str(
                        "manip",
                        match r.manip {
                            1 => "snat",
                            2 => "dnat",
                            _ => "snat+dnat",
                        },
                    )
                    .num("proto", r.proto)
                    .str(
                        "orig",
                        &format!(
                            "{} -> {}",
                            addr(r.family, &r.orig_src, r.orig_sport),
                            addr(r.family, &r.orig_dst, r.orig_dport)
                        ),
                    )
                    .str(
                        "reply",
                        &format!(
                            "{} -> {}",
                            addr(r.family, &r.reply_src, r.reply_sport),
                            addr(r.family, &r.reply_dst, r.reply_dport)
                        ),
                    )
                    .num("netns", r.netns)
            }
            other => panic!("unknown record type {other}"),
        };
        Some(line.done())
    }

    fn exec(&self, rec: &[u8], h: &types::rec_hdr, ts: u64) -> Obj {
        let r: types::exec_rec = read(rec);
        let body = &rec[size_of::<types::exec_rec>()..];
        let path = text(&body[..usize::from(r.path_len)]);
        let mut argv =
            &body[usize::from(r.path_len)..usize::from(r.path_len) + usize::from(r.argv_len)];
        if argv.last() == Some(&0) {
            argv = &argv[..argv.len() - 1];
        }
        let args: Vec<String> = if argv.is_empty() {
            Vec::new()
        } else {
            argv.split(|b| *b == 0).map(|a| quote(&text(a))).collect()
        };
        let prev = self
            .images
            .get(&(r.prev_image_proc, r.prev_image_seq))
            .cloned()
            .unwrap_or_default();
        let kind = if u32::from(h.flags) & types::rec_flag::FLAG_SNAPSHOT.0 != 0 {
            "process"
        } else {
            "exec"
        };
        Obj::new(kind, ts)
            .num("proc", r.proc)
            .num("seq", r.exec_seq)
            .num("spawner", r.spawner)
            .str(
                "prev_image",
                &format!("{}:{}", r.prev_image_proc, r.prev_image_seq),
            )
            .str("prev_exe", &prev)
            .num("parent", r.parent)
            .num("pid", r.pid)
            .num("ppid", r.ppid)
            .num("cgroup", r.cgroup)
            .raw(
                "container",
                self.containers
                    .get(&r.cgroup)
                    .map_or("null", String::as_str),
            )
            .str("path", &path)
            .raw("argv", &format!("[{}]", args.join(",")))
            .num("uid", r.uid)
            .num("euid", r.euid)
            .num("gid", r.gid)
            .num("egid", r.egid)
            .num("loginuid", r.loginuid)
            .num("sessionid", r.sessionid)
            .str("cap_eff", &format!("{:#x}", r.cap_eff))
            .str("exe_dev", &dev(r.exe_dev))
            .num("exe_ino", r.exe_ino)
            .num("exe_ctime", r.exe_ctime)
            .str("exe_mode", &format!("{:o}", r.exe_mode))
            .num("exe_nlink", r.exe_nlink)
            .str("exe_fs", &fs_name(r.exe_magic))
            .num("exe_upper", r.exe_flags & 1 != 0)
            .raw(
                "stdio_socket",
                &format!(
                    "[{},{},{}]",
                    r.exe_flags & 2 != 0,
                    r.exe_flags & 4 != 0,
                    r.exe_flags & 8 != 0
                ),
            )
            .str(
                "cwd",
                self.paths
                    .get(&(r.cwd_dev, r.cwd_ino))
                    .map_or("", String::as_str),
            )
            .str(
                "sha256",
                self.hashes
                    .get(&(r.exe_dev, r.exe_ino, r.exe_ctime))
                    .map_or("", String::as_str),
            )
            .str(
                "tty",
                &if r.tty == 0 {
                    String::new()
                } else {
                    dev(r.tty)
                },
            )
            .num(
                "truncated",
                u32::from(h.flags) & types::rec_flag::FLAG_TRUNCATED.0 != 0,
            )
    }

    fn admin(&self, rec: &[u8], ts: u64) -> Obj {
        use types::admin_op as op;
        let r: types::admin_rec = read(rec);
        let body = &rec[size_of::<types::admin_rec>()..];
        let (l0, l1) = (usize::from(r.len0), usize::from(r.len1));
        let (s0, s1) = (text(&body[..l0]), text(&body[l0..l0 + l1]));
        let [a0, a1, a2, a3] = r.arg;
        let ids = |lo: u64, hi: u64| {
            format!(
                "[{},{},{},{}]",
                lo & 0xffff_ffff,
                lo >> 32,
                hi & 0xffff_ffff,
                hi >> 32
            )
        };
        let obj = self.actor(Obj::new("admin", ts), &r.a);
        match op(r.op) {
            op::ADMIN_MODULE_FILE => obj
                .str("op", "module_load")
                .str("path", &s0)
                .str("dev", &dev(a0 as u32))
                .num("ino", a1),
            op::ADMIN_MODULE_DATA => obj.str("op", "module_load_memory"),
            op::ADMIN_KEXEC_FILE => obj
                .str("op", "kexec_load")
                .str("path", &s0)
                .str("dev", &dev(a0 as u32))
                .num("ino", a1),
            op::ADMIN_KEXEC_DATA => obj.str("op", "kexec_load_memory"),
            op::ADMIN_BPF_LOAD => obj
                .str("op", "bpf_load")
                .str("name", &s0)
                .num("prog_type", a0)
                .num("attach_type", a1)
                .num("insns", a2)
                .num("attach_btf_id", a3),
            op::ADMIN_PTRACE => obj
                .str("op", "ptrace")
                .num("target_proc", a0)
                .num("target_pid", a1)
                .str("mode", &format!("{a2:#x}")),
            op::ADMIN_TRACEME => obj
                .str("op", "ptrace_traceme")
                .num("tracer_proc", a0)
                .num("tracer_pid", a1),
            op::ADMIN_SETUID => obj
                .str("op", "setuid")
                .raw("old", &ids(a0, a2))
                .raw("new", &ids(a1, a3)),
            op::ADMIN_SETGID => obj
                .str("op", "setgid")
                .raw("old", &ids(a0, a2))
                .raw("new", &ids(a1, a3)),
            op::ADMIN_CAPSET => obj
                .str("op", "capset")
                .str("old_effective", &format!("{a0:#x}"))
                .str("effective", &format!("{a1:#x}"))
                .str("permitted", &format!("{a2:#x}"))
                .str("inheritable", &format!("{a3:#x}")),
            op::ADMIN_MOUNT => obj
                .str("op", "mount")
                .str("target", &s0)
                .str("source", &s1)
                .str("fstype", &fstype(a1, a2))
                .str("flags", &format!("{a0:#x}")),
            op::ADMIN_MOVE_MOUNT => obj
                .str("op", "move_mount")
                .str("target", &s0)
                .str("source", &s1),
            op::ADMIN_UMOUNT => obj
                .str("op", "umount")
                .str("fstype", &s0)
                .str("dev", &dev(a1 as u32))
                .str("flags", &format!("{a0:#x}")),
            op::ADMIN_PIVOT_ROOT => obj
                .str("op", "pivot_root")
                .str("new_root", &s0)
                .str("put_old", &s1),
            op::ADMIN_SETTIME => obj
                .str("op", "settime")
                .num("sec", a0 as i64)
                .num("nsec", a1),
            op::ADMIN_SYSCTL => {
                let mut parts: Vec<&str> = s0.split('\0').filter(|p| !p.is_empty()).collect();
                parts.reverse();
                let name = parts.join("/");
                let raw = &body[l0..l0 + l1];
                obj.str("op", "sysctl_write")
                    .str("name", name.strip_prefix("sys/").unwrap_or(&name))
                    .num("ret", a0 as i64)
                    .num("maxlen", a1 as i64)
                    .str("value", &sysctl_value(raw))
                    .str(
                        "value_hex",
                        &raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    )
            }
            op::ADMIN_NS_CREATE => obj
                .str("op", "ns_create")
                .raw("ns", &ns_names(a0))
                .num("for_child", a1 != 0)
                .num("netns", a2)
                .num("mntns", a3),
            op::ADMIN_SETNS => obj
                .str("op", "setns")
                .raw("ns", &ns_names(a0))
                .num("target_ns", a1),
            op::ADMIN_USERNS => obj.str("op", "userns_create").num("euid", a0),
            op::ADMIN_KILL => obj
                .str("op", "kill")
                .num("target_proc", a0)
                .num("target_pid", a1)
                .num("signal", a2),
            op::ADMIN_BPF_ACCESS => obj
                .str("op", "bpf_access")
                .str("object", if a0 == 0 { "map" } else { "prog" })
                .num("id", a1)
                .str("fmode", &format!("{a2:#x}")),
            op::ADMIN_ANON_INODE => obj.str("op", "anon_inode").str("name", &s0),
            other => panic!("unknown admin op {}", other.0),
        }
    }

    fn sock(&self, rec: &[u8], h: &types::rec_hdr, ts: u64) -> Obj {
        let r: types::sock_rec = read(rec);
        let payload = &rec[size_of::<types::sock_rec>()..][..usize::from(r.payload_len)];
        let kind = match u32::from(h.r#type) {
            CONNECT => "connect",
            ACCEPT => "accept",
            LISTEN => "listen",
            BIND => "bind",
            UDP_SEND => "udp_send",
            DNS_QUERY => "dns_query",
            _ => "dns_answer",
        };
        let obj = self
            .actor(Obj::new(kind, ts), &r.a)
            .num("proto", r.proto)
            .str("src", &addr(r.family, &r.saddr, r.sport))
            .str("dst", &addr(r.family, &r.daddr, r.dport))
            .num("netns", r.netns)
            .num("cookie", r.cookie)
            .num(
                "saturated",
                u32::from(h.flags) & types::rec_flag::FLAG_SATURATED.0 != 0,
            );
        match u32::from(h.r#type) {
            DNS_QUERY => match dns_question(payload) {
                Some((name, qtype, _)) => obj.str("qname", &name).num("qtype", qtype),
                None => obj,
            },
            DNS_ANSWER => match dns_answers(payload) {
                Some((name, answers)) => obj
                    .str("qname", &name)
                    .raw("answers", &format!("[{}]", answers.join(","))),
                None => obj,
            },
            _ => obj,
        }
    }
}

fn dns_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = usize::from(*msg.get(pos)?);
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(pos + 2);
            pos = (len & 0x3f) << 8 | usize::from(*msg.get(pos + 1)?);
            continue;
        }
        labels.push(text(msg.get(pos + 1..pos + 1 + len)?));
        pos += 1 + len;
    }
    None
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        msg.get(pos..pos + 2)?.try_into().unwrap(),
    ))
}

fn dns_question(msg: &[u8]) -> Option<(String, u16, usize)> {
    let (name, pos) = dns_name(msg, 12)?;
    Some((name, u16_at(msg, pos)?, pos + 4))
}

fn dns_answers(msg: &[u8]) -> Option<(String, Vec<String>)> {
    let (name, _, mut pos) = dns_question(msg)?;
    let mut answers = Vec::new();
    for _ in 0..u16_at(msg, 6)? {
        let (_, next) = dns_name(msg, pos)?;
        let (rtype, rdlen) = (u16_at(msg, next)?, usize::from(u16_at(msg, next + 8)?));
        let rdata = msg.get(next + 10..next + 10 + rdlen)?;
        match (rtype, rdlen) {
            (1, 4) => answers.push(quote(
                &Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
            )),
            (28, 16) => answers.push(quote(
                &Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).to_string(),
            )),
            (5, _) => answers.push(quote(&format!("CNAME {}", dns_name(msg, next + 10)?.0))),
            _ => {}
        }
        pos = next + 10 + rdlen;
    }
    Some((name, answers))
}
