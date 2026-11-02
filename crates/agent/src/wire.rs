use crate::bpf::types;

pub const MAGIC: &[u8; 8] = b"PANO\0\0\0\x01";
pub const HDR: usize = size_of::<types::rec_hdr>();

pub const REC_META: u8 = 100;
pub const REC_CLOCK: u8 = 101;
pub const REC_LOSS: u8 = 102;
pub const REC_WATCH: u8 = 103;

pub fn push(out: &mut Vec<u8>, ty: u8, jiffies: u64, parts: &[&[u8]]) {
    let body: usize = parts.iter().map(|p| p.len()).sum();
    let len = (HDR + body).next_multiple_of(8);
    out.extend_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
    out.push(ty);
    out.push(0);
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&jiffies.to_ne_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out.resize(out.len() + len - HDR - body, 0);
}

pub fn kernel_dev(dev: u64) -> u32 {
    (libc::major(dev) << 20) | libc::minor(dev)
}

pub fn read<T>(bytes: &[u8]) -> T {
    assert!(bytes.len() >= size_of::<T>());
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) }
}

pub fn bytes_of<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(value).cast(), size_of::<T>()) }
}
