use std::collections::HashMap;
use std::fmt::{Display, Write as _};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bpf::types;
use crate::wire::{self, read};

const EXEC: u32 = types::rec_type::REC_EXEC.0;
const CGROUP: u32 = types::rec_type::REC_CGROUP.0;
const CONNECT: u32 = types::rec_type::REC_CONNECT.0;
const ACCEPT: u32 = types::rec_type::REC_ACCEPT.0;
const LISTEN: u32 = types::rec_type::REC_LISTEN.0;
const UDP_SEND: u32 = types::rec_type::REC_UDP_SEND.0;
const DNS_QUERY: u32 = types::rec_type::REC_DNS_QUERY.0;
const DNS_ANSWER: u32 = types::rec_type::REC_DNS_ANSWER.0;
const FILE: u32 = types::rec_type::REC_FILE.0;
const FILE_REPEAT: u32 = types::rec_type::REC_FILE_REPEAT.0;
const META: u32 = wire::REC_META as u32;
const CLOCK: u32 = wire::REC_CLOCK as u32;
const LOSS: u32 = wire::REC_LOSS as u32;
const WATCH: u32 = wire::REC_WATCH as u32;

const MASKS: [(u32, &str); 14] = [
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
    hz: u64,
    images: HashMap<(u64, u64), String>,
    watches: HashMap<(u32, u64), String>,
    files: HashMap<FileKey, (types::actor, String)>,
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

fn dev(d: u32) -> String {
    format!("{}:{}", d >> 20, d & 0xfffff)
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
                let (jiffies, realtime): (u64, u64) =
                    (read(&rec[wire::HDR..]), read(&rec[wire::HDR + 8..]));
                self.clocks.push((jiffies, realtime / 1_000_000));
            }
            META => self.hz = u64::from(read::<u32>(&rec[wire::HDR + 4..])),
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
            EXEC => self.exec(rec, h, ts),
            CGROUP => {
                let r: types::cgroup_rec = read(rec);
                let body = &rec[size_of::<types::cgroup_rec>()..];
                Obj::new("cgroup", ts)
                    .num("id", r.id)
                    .str("path", &text(&body[..usize::from(r.path_len)]))
            }
            CONNECT | ACCEPT | LISTEN | UDP_SEND | DNS_QUERY | DNS_ANSWER => self.sock(rec, h, ts),
            FILE => {
                let r: types::file_rec = read(rec);
                let name = text(&rec[size_of::<types::file_rec>()..][..usize::from(r.name_len)]);
                self.file(
                    self.actor(Obj::new("file", ts), &r.a).str("name", &name),
                    &r.k,
                )
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
            .num(
                "truncated",
                u32::from(h.flags) & types::rec_flag::FLAG_TRUNCATED.0 != 0,
            )
    }

    fn sock(&self, rec: &[u8], h: &types::rec_hdr, ts: u64) -> Obj {
        let r: types::sock_rec = read(rec);
        let payload = &rec[size_of::<types::sock_rec>()..][..usize::from(r.payload_len)];
        let kind = match u32::from(h.r#type) {
            CONNECT => "connect",
            ACCEPT => "accept",
            LISTEN => "listen",
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
