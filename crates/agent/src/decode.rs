use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

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
const SNAPSHOT: u8 = types::rec_flag::FLAG_SNAPSHOT.0 as u8;
const TRUNCATED: u8 = types::rec_flag::FLAG_TRUNCATED.0 as u8;
const SATURATED: u8 = types::rec_flag::FLAG_SATURATED.0 as u8;

// Entries per generation of each streaming join table; a table keeps at most two generations, and
// an entry read in the older one moves to the newer.
const STREAM_CAP: usize = 1 << 15;
const HEX: &[u8; 16] = b"0123456789abcdef";

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

type FileKey = (u64, u64, u64, u64, u32, u32);

fn file_key(k: &types::file_key) -> FileKey {
    (k.proc, k.seq, k.ino, k.child_ino, k.dev, k.mask)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Otlp,
}

pub fn decode(path: &str, fmt: Format) {
    let data = fs::read(path).unwrap();
    assert_eq!(&data[..8], wire::MAGIC, "not a panopticon stream");
    let data = &data[8..];
    let mut out = BufWriter::new(io::stdout().lock());
    let mut line = Vec::new();
    match fmt {
        Format::Json => {
            let mut decoder = Decoder::new(Format::Json, usize::MAX, true);
            for (rec, h) in records(data) {
                decoder.index(rec, &h);
            }
            decoder.clocks.sort_unstable();
            for hashes in decoder.inode_hashes.values_mut() {
                hashes.sort_unstable();
            }
            for (rec, h) in records(data) {
                line.clear();
                if decoder.record(rec, &h, &mut line) {
                    line.push(b'\n');
                    out.write_all(&line).unwrap();
                }
            }
        }
        Format::Otlp => {
            let mut stream = Stream::new();
            let (mut start, mut end) = (0, 0);
            for (rec, h) in records(data) {
                end += rec.len();
                if u32::from(h.r#type) == CLOCK || end == data.len() {
                    line.clear();
                    stream.encode(&data[start..end], &mut line, b'\n');
                    if !line.is_empty() {
                        line.push(b'\n');
                        out.write_all(&line).unwrap();
                    }
                    start = end;
                }
            }
        }
    }
    out.flush().unwrap();
}

pub fn records(data: &[u8]) -> impl Iterator<Item = (&[u8], types::rec_hdr)> {
    let mut off = 0;
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

pub struct Stream {
    decoder: Decoder,
}

impl Stream {
    pub fn new() -> Self {
        Stream {
            decoder: Decoder::new(Format::Otlp, STREAM_CAP, false),
        }
    }

    pub fn encode(&mut self, batch: &[u8], out: &mut Vec<u8>, sep: u8) -> u64 {
        for (rec, h) in records(batch) {
            self.decoder.index(rec, &h);
        }
        let mut n = 0;
        for (rec, h) in records(batch) {
            let start = out.len();
            if start > 0 {
                out.push(sep);
            }
            if self.decoder.record(rec, &h, out) {
                n += 1;
            } else {
                out.truncate(start);
            }
        }
        let old = self.decoder.clocks.len().saturating_sub(1);
        self.decoder.clocks.drain(..old);
        n
    }

    pub fn loss(&self, out: &mut Vec<u8>, records: u64) {
        if !out.is_empty() {
            out.push(b',');
        }
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Obj::new(out, Format::Otlp, "sink_loss", u64::try_from(ms).unwrap())
            .num("records", records)
            .done();
    }

    pub fn body(&self, out: &mut Vec<u8>, records: &[u8]) {
        out.clear();
        out.extend_from_slice(br#"{"resourceLogs":[{"resource":{"attributes":["#);
        for (i, (key, value)) in [
            ("service.name", "panopticon"),
            ("host.name", self.decoder.host.as_str()),
            ("panopticon.boot_id", self.decoder.boot_id.as_str()),
        ]
        .into_iter()
        .enumerate()
        {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(br#"{"key":""#);
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(br#"","value":{"stringValue":"#);
            push_str(out, value);
            out.extend_from_slice(b"}}");
        }
        out.extend_from_slice(br#"]},"scopeLogs":[{"scope":{"name":"panopticon"},"logRecords":["#);
        out.extend_from_slice(records);
        out.extend_from_slice(b"]}]}]}");
    }
}

struct Gen<K, V> {
    cur: HashMap<K, V>,
    old: HashMap<K, V>,
    cap: usize,
}

impl<K: Hash + Eq + Copy, V> Gen<K, V> {
    fn new(cap: usize) -> Self {
        Gen {
            cur: HashMap::new(),
            old: HashMap::new(),
            cap,
        }
    }

    fn insert(&mut self, k: K, v: V) {
        if self.cur.len() >= self.cap {
            self.old = mem::take(&mut self.cur);
        }
        self.cur.insert(k, v);
    }

    fn get(&mut self, k: &K) -> Option<&V> {
        if !self.cur.contains_key(k) {
            let v = self.old.remove(k)?;
            self.insert(*k, v);
        }
        self.cur.get(k)
    }
}

struct Container {
    runtime: String,
    id: String,
    name: String,
    image: String,
    pod: String,
    namespace: String,
    flags: u8,
}

struct Obj<'a> {
    out: &'a mut Vec<u8>,
    fmt: Format,
}

impl<'a> Obj<'a> {
    fn new(out: &'a mut Vec<u8>, fmt: Format, kind: &str, ts: u64) -> Self {
        match fmt {
            Format::Json => {
                out.extend_from_slice(br#"{"type":""#);
                out.extend_from_slice(kind.as_bytes());
                out.extend_from_slice(br#"","ts":"#);
                push_int(out, ts.into());
            }
            Format::Otlp => {
                out.extend_from_slice(br#"{"timeUnixNano":""#);
                push_int(out, i128::from(ts) * 1_000_000);
                out.extend_from_slice(br#"","eventName":"pano."#);
                out.extend_from_slice(kind.as_bytes());
                out.extend_from_slice(br#"","attributes":[{"key":"type","value":{"stringValue":""#);
                out.extend_from_slice(kind.as_bytes());
                out.extend_from_slice(br#""}}"#);
            }
        }
        Obj { out, fmt }
    }

    fn open(&mut self, key: &str, otlp: &[u8]) {
        match self.fmt {
            Format::Json => {
                self.out.extend_from_slice(b",\"");
                self.out.extend_from_slice(key.as_bytes());
                self.out.extend_from_slice(b"\":");
            }
            Format::Otlp => {
                self.out.extend_from_slice(br#",{"key":""#);
                self.out.extend_from_slice(key.as_bytes());
                self.out.extend_from_slice(br#"","value":{"#);
                self.out.extend_from_slice(otlp);
            }
        }
    }

    fn close(&mut self) {
        if self.fmt == Format::Otlp {
            self.out.extend_from_slice(b"}}");
        }
    }

    fn num(mut self, key: &str, value: impl Into<i128>) -> Self {
        let quoted = self.fmt == Format::Otlp;
        self.open(key, br#""intValue":"#);
        if quoted {
            self.out.push(b'"');
        }
        push_int(self.out, value.into());
        if quoted {
            self.out.push(b'"');
        }
        self.close();
        self
    }

    fn flag(mut self, key: &str, value: bool) -> Self {
        if self.fmt == Format::Otlp && !value {
            return self;
        }
        self.open(key, br#""boolValue":"#);
        self.out
            .extend_from_slice(if value { b"true" } else { b"false" });
        self.close();
        self
    }

    fn str(mut self, key: &str, value: &str) -> Self {
        if self.fmt == Format::Otlp && value.is_empty() {
            return self;
        }
        self.open(key, br#""stringValue":"#);
        push_str(self.out, value);
        self.close();
        self
    }

    fn with(mut self, key: &str, ascii: impl FnOnce(&mut Vec<u8>)) -> Self {
        self.open(key, br#""stringValue":"#);
        self.out.push(b'"');
        ascii(self.out);
        self.out.push(b'"');
        self.close();
        self
    }

    fn array<T>(
        mut self,
        key: &str,
        otlp: &[u8],
        items: impl IntoIterator<Item = T>,
        mut push: impl FnMut(&mut Vec<u8>, T),
    ) -> Self {
        let wrap = self.fmt == Format::Otlp;
        self.open(key, br#""arrayValue":{"values":"#);
        self.out.push(b'[');
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                self.out.push(b',');
            }
            if wrap {
                self.out.push(b'{');
                self.out.extend_from_slice(otlp);
            }
            push(self.out, item);
            if wrap {
                self.out.push(b'}');
            }
        }
        self.out.push(b']');
        if wrap {
            self.out.push(b'}');
        }
        self.close();
        self
    }

    fn strs<S: AsRef<str>>(self, key: &str, items: impl IntoIterator<Item = S>) -> Self {
        self.array(key, br#""stringValue":"#, items, |out, s| {
            push_str(out, s.as_ref());
        })
    }

    fn nums(self, key: &str, items: &[u64]) -> Self {
        let quoted = self.fmt == Format::Otlp;
        self.array(key, br#""intValue":"#, items, |out, &v| {
            if quoted {
                out.push(b'"');
            }
            push_int(out, v.into());
            if quoted {
                out.push(b'"');
            }
        })
    }

    fn bools(self, key: &str, items: &[bool]) -> Self {
        self.array(key, br#""boolValue":"#, items, |out, &v| {
            out.extend_from_slice(if v { b"true" } else { b"false" });
        })
    }

    fn container(mut self, c: Option<&Container>) -> Self {
        let bit = |c: &Container, b: u8| c.flags & b != 0;
        match (self.fmt, c) {
            (Format::Json, None) => {
                self.open("container", b"");
                self.out.extend_from_slice(b"null");
                self
            }
            (Format::Json, Some(c)) => {
                self.open("container", b"");
                self.out.push(b'{');
                for (i, (k, v)) in [
                    ("runtime", &c.runtime),
                    ("id", &c.id),
                    ("name", &c.name),
                    ("image", &c.image),
                    ("pod", &c.pod),
                    ("namespace", &c.namespace),
                ]
                .into_iter()
                .enumerate()
                {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.out.push(b'"');
                    self.out.extend_from_slice(k.as_bytes());
                    self.out.extend_from_slice(b"\":");
                    push_str(self.out, v);
                }
                for (k, b) in [
                    ("privileged", container::PRIVILEGED),
                    ("host_pid", container::HOST_PID),
                    ("host_net", container::HOST_NET),
                    ("sandbox", container::SANDBOX),
                ] {
                    self.out.extend_from_slice(b",\"");
                    self.out.extend_from_slice(k.as_bytes());
                    self.out.extend_from_slice(b"\":");
                    self.out
                        .extend_from_slice(if bit(c, b) { b"true" } else { b"false" });
                }
                self.out.push(b'}');
                self
            }
            (Format::Otlp, None) => self,
            (Format::Otlp, Some(c)) => self
                .str("container.runtime", &c.runtime)
                .str("container.id", &c.id)
                .str("container.name", &c.name)
                .str("container.image", &c.image)
                .str("container.pod", &c.pod)
                .str("container.namespace", &c.namespace)
                .flag("container.privileged", bit(c, container::PRIVILEGED))
                .flag("container.host_pid", bit(c, container::HOST_PID))
                .flag("container.host_net", bit(c, container::HOST_NET))
                .flag("container.sandbox", bit(c, container::SANDBOX)),
        }
    }

    fn done(self) {
        match self.fmt {
            Format::Json => self.out.push(b'}'),
            Format::Otlp => self.out.extend_from_slice(b"]}"),
        }
    }
}

fn push_int(out: &mut Vec<u8>, v: i128) {
    if v < 0 {
        out.push(b'-');
    }
    let mut n = v.unsigned_abs();
    let mut digits = [0u8; 40];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b >= 0x20 && b != b'"' && b != b'\\' {
            continue;
        }
        out.extend_from_slice(&bytes[start..i]);
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0xf)]);
            }
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

fn push_hex(out: &mut Vec<u8>, v: u64) {
    write!(out, "{v:#x}").unwrap();
}

fn push_dev(out: &mut Vec<u8>, d: u32) {
    push_int(out, (d >> 20).into());
    out.push(b':');
    push_int(out, (d & 0xfffff).into());
}

fn push_pair(out: &mut Vec<u8>, a: u64, b: u64) {
    push_int(out, a.into());
    out.push(b':');
    push_int(out, b.into());
}

fn push_addr(out: &mut Vec<u8>, family: u8, raw: &[u8; 16], port: u16) {
    if family == 10 {
        write!(out, "[{}]:{port}", Ipv6Addr::from(*raw)).unwrap();
    } else {
        write!(
            out,
            "{}:{port}",
            Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])
        )
        .unwrap();
    }
}

fn push_fs(out: &mut Vec<u8>, magic: u32) {
    match FS_MAGIC.iter().find(|(m, _)| *m == magic) {
        Some((_, name)) => out.extend_from_slice(name.as_bytes()),
        None => push_hex(out, magic.into()),
    }
}

fn text(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

fn sysctl_value(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    if end >= 2
        && raw[..end]
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ')
    {
        return text(&raw[..end]).into_owned();
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

fn fstype(a: u64, b: u64) -> String {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_ne_bytes());
    bytes[8..].copy_from_slice(&b.to_ne_bytes());
    text(&bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(16)]).into_owned()
}

fn path_text(raw: &[u8]) -> String {
    let s = text(raw);
    if s.starts_with('/') {
        return s.into_owned();
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

fn container_rec(rec: &[u8]) -> (u64, Container) {
    let (cgroup, flags): (u64, u8) = (read(&rec[wire::HDR..]), rec[wire::HDR + 8]);
    let text = text(&rec[wire::HDR + 16..]);
    let mut parts = text.split('\0');
    let mut field = || parts.next().unwrap_or_default().to_string();
    let c = Container {
        runtime: field(),
        id: field(),
        name: field(),
        image: field(),
        pod: field(),
        namespace: field(),
        flags,
    };
    (cgroup, c)
}

fn meta_rec(rec: &[u8]) -> (u32, u32, String, String) {
    let (ncpus, hz): (u32, u32) = (read(&rec[wire::HDR..]), read(&rec[wire::HDR + 4..]));
    let (boot_len, host_len): (u16, u16) =
        (read(&rec[wire::HDR + 8..]), read(&rec[wire::HDR + 10..]));
    let body = &rec[wire::HDR + 16..];
    let (boot, host) = (usize::from(boot_len), usize::from(host_len));
    (
        ncpus,
        hz,
        text(&body[..boot]).into_owned(),
        text(&body[boot..boot + host]).into_owned(),
    )
}

struct Decoder {
    fmt: Format,
    joins: bool,
    clocks: Vec<(u64, u64)>,
    boot_to_real_ms: i128,
    hz: u64,
    host: String,
    boot_id: String,
    images: Gen<(u64, u64), String>,
    watches: Gen<(u32, u64), String>,
    files: Gen<FileKey, (types::actor, String)>,
    containers: Gen<u64, Container>,
    paths: Gen<(u32, u64), String>,
    hashes: HashMap<(u32, u64, i64), String>,
    inode_hashes: HashMap<(u32, u64), Vec<(u64, String)>>,
}

impl Decoder {
    fn new(fmt: Format, cap: usize, joins: bool) -> Self {
        Decoder {
            fmt,
            joins,
            clocks: Vec::new(),
            boot_to_real_ms: 0,
            hz: 0,
            host: String::new(),
            boot_id: String::new(),
            images: Gen::new(cap),
            watches: Gen::new(cap),
            files: Gen::new(cap),
            containers: Gen::new(cap),
            paths: Gen::new(cap),
            hashes: HashMap::new(),
            inode_hashes: HashMap::new(),
        }
    }

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
            META => {
                let (_, hz, boot_id, host) = meta_rec(rec);
                self.hz = u64::from(hz);
                self.boot_id = boot_id;
                self.host = host;
            }
            PATH => {
                let r: types::path_rec = read(rec);
                let raw = &rec[size_of::<types::path_rec>()..][..usize::from(r.len)];
                self.paths.insert((r.dev, r.ino), path_text(raw));
            }
            HASH if self.joins => {
                let (key, _, digest) = hash_rec(rec);
                self.inode_hashes
                    .entry((key.0, key.1))
                    .or_default()
                    .push((h.jiffies, digest.clone()));
                self.hashes.insert(key, digest);
            }
            CONTAINER => {
                let (cgroup, c) = container_rec(rec);
                self.containers.insert(cgroup, c);
            }
            WATCH => {
                let (d, ino): (u32, u64) = (read(&rec[wire::HDR..]), read(&rec[wire::HDR + 8..]));
                let path = text(&rec[wire::HDR + 16..]);
                self.watches
                    .insert((d, ino), path.trim_end_matches('\0').to_string());
            }
            EXEC => {
                let r: types::exec_rec = read(rec);
                let path = text(&rec[size_of::<types::exec_rec>()..][..usize::from(r.path_len)]);
                self.images.insert((r.proc, r.exec_seq), path.into_owned());
            }
            FILE => {
                let r: types::file_rec = read(rec);
                let key = file_key(&r.k);
                if self.files.get(&key).is_none() {
                    let name =
                        text(&rec[size_of::<types::file_rec>()..][..usize::from(r.name_len)]);
                    self.files.insert(key, (r.a, name.into_owned()));
                }
            }
            _ => {}
        }
    }

    fn ts(&self, jiffies: u64) -> u64 {
        let i = self.clocks.partition_point(|&(j, _)| j <= jiffies).max(1) - 1;
        let (clock_jiffies, clock_ms) = self.clocks[i];
        let delta = i128::from(jiffies) - i128::from(clock_jiffies);
        (i128::from(clock_ms) + delta * 1000 / i128::from(self.hz.max(1))) as u64
    }

    fn actor<'o>(&mut self, obj: Obj<'o>, a: &types::actor) -> Obj<'o> {
        let exe = self
            .images
            .get(&(a.image_proc, a.image_seq))
            .map_or("", String::as_str);
        obj.num("proc", a.proc)
            .with("image", |o| push_pair(o, a.image_proc, a.image_seq))
            .str("exe", exe)
            .num("cgroup", a.cgroup)
            .container(self.containers.get(&a.cgroup))
            .num("pid", a.pid)
            .num("tid", a.tid)
    }

    fn file<'o>(&mut self, obj: Obj<'o>, k: &types::file_key) -> Obj<'o> {
        let path = self.watches.get(&(k.dev, k.ino)).map_or("", String::as_str);
        obj.str("path", path)
            .with("dev", |o| push_dev(o, k.dev))
            .num("ino", k.ino)
            .num("child_ino", k.child_ino)
            .strs(
                "mask",
                MASKS
                    .iter()
                    .filter(|(bit, _)| k.mask & bit != 0)
                    .map(|(_, n)| *n),
            )
    }

    fn record(&mut self, rec: &[u8], h: &types::rec_hdr, out: &mut Vec<u8>) -> bool {
        let ts = self.ts(h.jiffies);
        let fmt = self.fmt;
        match u32::from(h.r#type) {
            CLOCK => return false,
            META => {
                let (ncpus, hz, boot_id, host) = meta_rec(rec);
                Obj::new(out, fmt, "meta", ts)
                    .num("ncpus", ncpus)
                    .num("hz", hz)
                    .str("boot_id", &boot_id)
                    .str("host", &host)
                    .done();
            }
            PATH => {
                let r: types::path_rec = read(rec);
                let raw = &rec[size_of::<types::path_rec>()..][..usize::from(r.len)];
                Obj::new(out, fmt, "path", ts)
                    .with("dev", |o| push_dev(o, r.dev))
                    .num("ino", r.ino)
                    .str("path", &path_text(raw))
                    .done();
            }
            HASH => {
                let ((dev_id, ino, ctime), size, digest) = hash_rec(rec);
                Obj::new(out, fmt, "hash", ts)
                    .with("dev", |o| push_dev(o, dev_id))
                    .num("ino", ino)
                    .num("ctime", ctime)
                    .num("size", size)
                    .str("sha256", &digest)
                    .done();
            }
            CONTAINER => {
                let (cgroup, c) = container_rec(rec);
                Obj::new(out, fmt, "container", ts)
                    .num("cgroup", cgroup)
                    .container(Some(&c))
                    .done();
            }
            WATCH => {
                let (d, mask, ino): (u32, u32, u64) = (
                    read(&rec[wire::HDR..]),
                    read(&rec[wire::HDR + 4..]),
                    read(&rec[wire::HDR + 8..]),
                );
                let path = text(&rec[wire::HDR + 16..]);
                Obj::new(out, fmt, "watch", ts)
                    .str("path", path.trim_end_matches('\0'))
                    .with("dev", |o| push_dev(o, d))
                    .num("ino", ino)
                    .num("mask", mask)
                    .done();
            }
            LOSS => {
                let (class, cpu, drops): (u32, u32, u64) = (
                    read(&rec[wire::HDR..]),
                    read(&rec[wire::HDR + 4..]),
                    read(&rec[wire::HDR + 8..]),
                );
                Obj::new(out, fmt, "loss", ts)
                    .num("class", class)
                    .num("cpu", cpu)
                    .num("drops", drops)
                    .done();
            }
            MISS => {
                let count: u64 = read(&rec[wire::HDR..]);
                let name = &rec[wire::HDR + 8..];
                let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                Obj::new(out, fmt, "miss", ts)
                    .str("prog", &text(name))
                    .num("count", count)
                    .done();
            }
            EXEC => self.exec(rec, h, ts, out),
            CGROUP => {
                let r: types::cgroup_rec = read(rec);
                let body = &rec[size_of::<types::cgroup_rec>()..];
                Obj::new(out, fmt, "cgroup", ts)
                    .num("id", r.id)
                    .str("path", &text(&body[..usize::from(r.path_len)]))
                    .done();
            }
            CONNECT | ACCEPT | LISTEN | BIND | UDP_SEND | DNS_QUERY | DNS_ANSWER => {
                self.sock(rec, h, ts, out);
            }
            FILE => {
                let r: types::file_rec = read(rec);
                let name = text(&rec[size_of::<types::file_rec>()..][..usize::from(r.name_len)]);
                let sha256 = if r.k.mask & (0x8 | 0x80) != 0 {
                    self.inode_hashes
                        .get(&(r.k.dev, r.k.child_ino))
                        .and_then(|v| v.iter().find(|(j, _)| *j >= h.jiffies))
                        .map(|(_, d)| d.clone())
                } else {
                    None
                };
                let obj = self
                    .actor(Obj::new(out, fmt, "file", ts), &r.a)
                    .str("name", &name);
                self.file(obj, &r.k)
                    .flag("saturated", h.flags & SATURATED != 0)
                    .str("sha256", sha256.as_deref().unwrap_or_default())
                    .done();
            }
            FILE_REPEAT => {
                let r: types::file_repeat_rec = read(rec);
                let known = self
                    .files
                    .get(&file_key(&r.k))
                    .map(|(a, name)| (*a, name.clone()));
                let obj = Obj::new(out, fmt, "file_repeat", ts).num("count", r.count);
                let obj = match known {
                    Some((a, name)) => self.actor(obj, &a).str("name", &name),
                    None => obj.num("proc", r.k.proc),
                };
                self.file(obj, &r.k).done();
            }
            EXIT => {
                let r: types::exit_rec = read(rec);
                let code = r.exit_code;
                let obj = self
                    .actor(Obj::new(out, fmt, "exit", ts), &r.a)
                    .num(
                        "start",
                        i128::from(r.start_boottime / 1_000_000) + self.boot_to_real_ms,
                    )
                    .num("cpu_ms", r.cpu_ns / 1_000_000);
                if code & 0x7f != 0 {
                    obj.num("signal", code & 0x7f)
                        .flag("core", code & 0x80 != 0)
                        .done();
                } else {
                    obj.num("status", (code >> 8) & 0xff).done();
                }
            }
            LOGIN => {
                let r: types::login_rec = read(rec);
                self.actor(Obj::new(out, fmt, "login", ts), &r.a)
                    .num("loginuid", r.loginuid)
                    .num("sessionid", r.sessionid)
                    .done();
            }
            ADMIN => self.admin(rec, ts, out),
            RAW_SOCKET => {
                let r: types::raw_rec = read(rec);
                let family = match r.family {
                    2 => "inet",
                    10 => "inet6",
                    17 => "packet",
                    _ => "other",
                };
                self.actor(Obj::new(out, fmt, "raw_socket", ts), &r.a)
                    .str("family", family)
                    .num("sock_type", r.r#type)
                    .with("protocol", |o| push_hex(o, r.protocol.into()))
                    .num("netns", r.netns)
                    .done();
            }
            UNIX_CONNECT => {
                let r: types::unix_rec = read(rec);
                let path = self
                    .watches
                    .get(&(r.dev, r.ino))
                    .cloned()
                    .unwrap_or_default();
                self.actor(Obj::new(out, fmt, "unix_connect", ts), &r.a)
                    .str("path", &path)
                    .with("dev", |o| push_dev(o, r.dev))
                    .num("ino", r.ino)
                    .done();
            }
            NAT => {
                let r: types::nat_rec = read(rec);
                Obj::new(out, fmt, "nat", ts)
                    .str(
                        "manip",
                        match r.manip {
                            1 => "snat",
                            2 => "dnat",
                            _ => "snat+dnat",
                        },
                    )
                    .num("proto", r.proto)
                    .with("orig", |o| {
                        push_addr(o, r.family, &r.orig_src, r.orig_sport);
                        o.extend_from_slice(b" -> ");
                        push_addr(o, r.family, &r.orig_dst, r.orig_dport);
                    })
                    .with("reply", |o| {
                        push_addr(o, r.family, &r.reply_src, r.reply_sport);
                        o.extend_from_slice(b" -> ");
                        push_addr(o, r.family, &r.reply_dst, r.reply_dport);
                    })
                    .num("netns", r.netns)
                    .done();
            }
            other => panic!("unknown record type {other}"),
        }
        true
    }

    fn exec(&mut self, rec: &[u8], h: &types::rec_hdr, ts: u64, out: &mut Vec<u8>) {
        let r: types::exec_rec = read(rec);
        let body = &rec[size_of::<types::exec_rec>()..];
        let path = text(&body[..usize::from(r.path_len)]);
        let mut argv =
            &body[usize::from(r.path_len)..usize::from(r.path_len) + usize::from(r.argv_len)];
        if argv.last() == Some(&0) {
            argv = &argv[..argv.len() - 1];
        }
        let args = argv
            .split(|b| *b == 0)
            .filter(|_| !argv.is_empty())
            .map(text);
        let kind = if h.flags & SNAPSHOT != 0 {
            "process"
        } else {
            "exec"
        };
        let prev = self
            .images
            .get(&(r.prev_image_proc, r.prev_image_seq))
            .map_or("", String::as_str);
        let obj = Obj::new(out, self.fmt, kind, ts)
            .num("proc", r.proc)
            .num("seq", r.exec_seq)
            .num("spawner", r.spawner)
            .with("prev_image", |o| {
                push_pair(o, r.prev_image_proc, r.prev_image_seq);
            })
            .str("prev_exe", prev)
            .num("parent", r.parent)
            .num("pid", r.pid)
            .num("ppid", r.ppid)
            .num("cgroup", r.cgroup)
            .container(self.containers.get(&r.cgroup))
            .str("path", &path)
            .strs("argv", args)
            .num("uid", r.uid)
            .num("euid", r.euid)
            .num("gid", r.gid)
            .num("egid", r.egid)
            .num("loginuid", r.loginuid)
            .num("sessionid", r.sessionid)
            .with("cap_eff", |o| push_hex(o, r.cap_eff))
            .with("exe_dev", |o| push_dev(o, r.exe_dev))
            .num("exe_ino", r.exe_ino)
            .num("exe_ctime", r.exe_ctime)
            .with("exe_mode", |o| write!(o, "{:o}", r.exe_mode).unwrap())
            .num("exe_nlink", r.exe_nlink)
            .with("exe_fs", |o| push_fs(o, r.exe_magic))
            .flag("exe_upper", r.exe_flags & 1 != 0)
            .bools(
                "stdio_socket",
                &[
                    r.exe_flags & 2 != 0,
                    r.exe_flags & 4 != 0,
                    r.exe_flags & 8 != 0,
                ],
            );
        let cwd = self
            .paths
            .get(&(r.cwd_dev, r.cwd_ino))
            .map_or("", String::as_str);
        let sha256 = self
            .hashes
            .get(&(r.exe_dev, r.exe_ino, r.exe_ctime))
            .map_or("", String::as_str);
        let obj = obj.str("cwd", cwd).str("sha256", sha256);
        let obj = if r.tty == 0 {
            obj.str("tty", "")
        } else {
            obj.with("tty", |o| push_dev(o, r.tty))
        };
        obj.flag("truncated", h.flags & TRUNCATED != 0).done();
    }

    fn admin(&mut self, rec: &[u8], ts: u64, out: &mut Vec<u8>) {
        use types::admin_op as op;
        let r: types::admin_rec = read(rec);
        let body = &rec[size_of::<types::admin_rec>()..];
        let (l0, l1) = (usize::from(r.len0), usize::from(r.len1));
        let (s0, s1) = (text(&body[..l0]), text(&body[l0..l0 + l1]));
        let [a0, a1, a2, a3] = r.arg;
        let ids = |lo: u64, hi: u64| [lo & 0xffff_ffff, lo >> 32, hi & 0xffff_ffff, hi >> 32];
        let ns = |flags: u64| {
            NAMESPACES
                .iter()
                .filter(move |(bit, _)| flags & bit != 0)
                .map(|(_, n)| *n)
        };
        let obj = self.actor(Obj::new(out, self.fmt, "admin", ts), &r.a);
        let obj = match op(r.op) {
            op::ADMIN_MODULE_FILE => obj
                .str("op", "module_load")
                .str("path", &s0)
                .with("dev", |o| push_dev(o, a0 as u32))
                .num("ino", a1),
            op::ADMIN_MODULE_DATA => obj.str("op", "module_load_memory"),
            op::ADMIN_KEXEC_FILE => obj
                .str("op", "kexec_load")
                .str("path", &s0)
                .with("dev", |o| push_dev(o, a0 as u32))
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
                .with("mode", |o| push_hex(o, a2)),
            op::ADMIN_TRACEME => obj
                .str("op", "ptrace_traceme")
                .num("tracer_proc", a0)
                .num("tracer_pid", a1),
            op::ADMIN_SETUID => obj
                .str("op", "setuid")
                .nums("old", &ids(a0, a2))
                .nums("new", &ids(a1, a3)),
            op::ADMIN_SETGID => obj
                .str("op", "setgid")
                .nums("old", &ids(a0, a2))
                .nums("new", &ids(a1, a3)),
            op::ADMIN_CAPSET => obj
                .str("op", "capset")
                .with("old_effective", |o| push_hex(o, a0))
                .with("effective", |o| push_hex(o, a1))
                .with("permitted", |o| push_hex(o, a2))
                .with("inheritable", |o| push_hex(o, a3)),
            op::ADMIN_MOUNT => obj
                .str("op", "mount")
                .str("target", &s0)
                .str("source", &s1)
                .str("fstype", &fstype(a1, a2))
                .with("flags", |o| push_hex(o, a0)),
            op::ADMIN_MOVE_MOUNT => obj
                .str("op", "move_mount")
                .str("target", &s0)
                .str("source", &s1),
            op::ADMIN_UMOUNT => obj
                .str("op", "umount")
                .str("fstype", &s0)
                .with("dev", |o| push_dev(o, a1 as u32))
                .with("flags", |o| push_hex(o, a0)),
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
                    .with("value_hex", |o| {
                        for b in raw {
                            o.push(HEX[usize::from(b >> 4)]);
                            o.push(HEX[usize::from(b & 0xf)]);
                        }
                    })
            }
            op::ADMIN_NS_CREATE => obj
                .str("op", "ns_create")
                .strs("ns", ns(a0))
                .flag("for_child", a1 != 0)
                .num("netns", a2)
                .num("mntns", a3),
            op::ADMIN_SETNS => obj
                .str("op", "setns")
                .strs("ns", ns(a0))
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
                .with("fmode", |o| push_hex(o, a2)),
            op::ADMIN_ANON_INODE => obj.str("op", "anon_inode").str("name", &s0),
            other => panic!("unknown admin op {}", other.0),
        };
        obj.done();
    }

    fn sock(&mut self, rec: &[u8], h: &types::rec_hdr, ts: u64, out: &mut Vec<u8>) {
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
            .actor(Obj::new(out, self.fmt, kind, ts), &r.a)
            .num("proto", r.proto)
            .with("src", |o| push_addr(o, r.family, &r.saddr, r.sport))
            .with("dst", |o| push_addr(o, r.family, &r.daddr, r.dport))
            .num("netns", r.netns)
            .num("cookie", r.cookie)
            .flag("saturated", h.flags & SATURATED != 0);
        let obj = match u32::from(h.r#type) {
            DNS_QUERY => match dns_question(payload) {
                Some((name, qtype, _)) => obj.str("qname", &name).num("qtype", qtype),
                None => obj,
            },
            DNS_ANSWER => match dns_answers(payload) {
                Some((name, answers)) => obj.str("qname", &name).strs("answers", answers),
                None => obj,
            },
            _ => obj,
        };
        obj.done();
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
            (1, 4) => {
                answers.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
            }
            (28, 16) => {
                answers.push(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).to_string());
            }
            (5, _) => answers.push(format!("CNAME {}", dns_name(msg, next + 10)?.0)),
            _ => {}
        }
        pos = next + 10 + rdlen;
    }
    Some((name, answers))
}
