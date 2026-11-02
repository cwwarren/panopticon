use std::env;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/agent.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let btf = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .unwrap();
    assert!(btf.status.success(), "bpftool btf dump failed");
    std::fs::write(out.join("vmlinux.h"), btf.stdout).unwrap();
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([format!("-I{}", out.display()), "-mcpu=v4".into()])
        .build_and_generate(out.join("agent.skel.rs"))
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
