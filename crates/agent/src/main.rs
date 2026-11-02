mod bpf {
    include!(concat!(env!("OUT_DIR"), "/agent.skel.rs"));
}
mod container;
mod decode;
mod hash;
mod run;
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
        ["decode", path] => decode::decode(path),
        _ => {
            eprintln!(
                "usage: panopticon run <output> [poll-ms]\n       panopticon decode <output>"
            );
            process::exit(2);
        }
    }
}
