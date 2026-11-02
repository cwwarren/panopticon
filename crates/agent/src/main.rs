mod bpf {
    include!(concat!(env!("OUT_DIR"), "/agent.skel.rs"));
}
mod container;
mod decode;
mod hash;
mod run;
mod ship;
mod nat_bpf {
    include!(concat!(env!("OUT_DIR"), "/nat.skel.rs"));
}
mod wire;

use std::env;
use std::process;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["run", out] => run::run(out, Duration::from_millis(10)),
        ["run", out, poll_ms] => run::run(out, Duration::from_millis(poll_ms.parse().unwrap())),
        ["decode", path] => decode::decode(path, decode::Format::Json),
        ["decode", path, "otlp"] => decode::decode(path, decode::Format::Otlp),
        _ => {
            eprintln!(
                "usage: panopticon run <file | http://collector:4318> [poll-ms]\n       panopticon decode <file> [otlp]"
            );
            process::exit(2);
        }
    }
}
