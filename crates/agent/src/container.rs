use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::wire;

pub const PRIVILEGED: u8 = 1;
pub const HOST_PID: u8 = 2;
pub const HOST_NET: u8 = 4;
pub const SANDBOX: u8 = 8;

const CONTAINERD_BUNDLES: &[&str] = &[
    "/run/containerd/io.containerd.runtime.v2.task",
    "/run/k3s/containerd/io.containerd.runtime.v2.task",
];
const STORAGE: &[&str] = &[
    "/run/containers/storage/overlay-containers",
    "/var/lib/containers/storage/overlay-containers",
];

#[derive(Default)]
struct Meta {
    runtime: &'static str,
    id: String,
    name: String,
    image: String,
    pod: String,
    namespace: String,
    flags: u8,
}

pub fn push(buf: &mut Vec<u8>, jiffies: u64, cgroup: u64, path: &str) {
    let Some(meta) = resolve(path) else {
        return;
    };
    let strings = [
        meta.runtime,
        &meta.id,
        &meta.name,
        &meta.image,
        &meta.pod,
        &meta.namespace,
    ]
    .join("\0");
    wire::push(
        buf,
        wire::REC_CONTAINER,
        jiffies,
        &[
            &cgroup.to_ne_bytes(),
            &[meta.flags, 0, 0, 0, 0, 0, 0, 0],
            strings.as_bytes(),
        ],
    );
}

fn resolve(path: &str) -> Option<Meta> {
    let last = path.rsplit('/').next()?;
    let (runtime, id) = if let Some(id) = scope(last, "docker-") {
        ("docker", id)
    } else if let Some(id) = scope(last, "cri-containerd-") {
        ("containerd", id)
    } else if let Some(id) = scope(last, "crio-") {
        ("cri-o", id)
    } else if let Some(id) = scope(last, "libpod-") {
        ("podman", id)
    } else if is_id(last) && path.contains("/docker/") {
        ("docker", last)
    } else if is_id(last) && path.contains("kubepods") {
        ("containerd", last)
    } else {
        return None;
    };
    let mut meta = Meta {
        runtime,
        id: id.to_string(),
        ..Meta::default()
    };
    if runtime == "docker" {
        docker(&mut meta);
    } else {
        oci(&mut meta);
    }
    Some(meta)
}

fn scope<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let id = name.strip_prefix(prefix)?.strip_suffix(".scope")?;
    is_id(id).then_some(id)
}

fn is_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn json(path: &Path) -> Option<Value> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => {
            eprintln!("container metadata {path:?}: {err}");
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(err) => {
            eprintln!("container metadata {path:?}: {err}");
            None
        }
    }
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

fn first(annotations: &Value, keys: &[&str]) -> String {
    keys.iter()
        .map(|k| text(&annotations[*k]))
        .find(|v| !v.is_empty())
        .unwrap_or_default()
}

fn docker(meta: &mut Meta) {
    let dir = Path::new("/var/lib/docker/containers").join(&meta.id);
    if let Some(config) = json(&dir.join("config.v2.json")) {
        meta.name = text(&config["Name"]).trim_start_matches('/').to_string();
        meta.image = text(&config["Config"]["Image"]);
    }
    if let Some(host) = json(&dir.join("hostconfig.json")) {
        if host["Privileged"] == true {
            meta.flags |= PRIVILEGED;
        }
        if host["PidMode"] == "host" {
            meta.flags |= HOST_PID;
        }
        if host["NetworkMode"] == "host" {
            meta.flags |= HOST_NET;
        }
    }
}

fn bundle(meta: &Meta) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = if meta.runtime == "containerd" {
        CONTAINERD_BUNDLES
            .iter()
            .flat_map(|root| fs::read_dir(root).into_iter().flatten())
            .map(|ns| ns.unwrap().path().join(&meta.id).join("config.json"))
            .collect()
    } else {
        STORAGE
            .iter()
            .map(|root| Path::new(root).join(&meta.id).join("userdata/config.json"))
            .collect()
    };
    candidates.into_iter().find(|p| p.exists())
}

fn oci(meta: &mut Meta) {
    let Some(spec) = bundle(meta).and_then(|p| json(&p)) else {
        return;
    };
    let ann = &spec["annotations"];
    meta.name = first(
        ann,
        &[
            "io.kubernetes.cri.container-name",
            "io.kubernetes.container.name",
        ],
    );
    meta.pod = first(
        ann,
        &["io.kubernetes.cri.sandbox-name", "io.kubernetes.pod.name"],
    );
    meta.namespace = first(
        ann,
        &[
            "io.kubernetes.cri.sandbox-namespace",
            "io.kubernetes.pod.namespace",
        ],
    );
    meta.image = first(
        ann,
        &[
            "io.kubernetes.cri.image-name",
            "io.kubernetes.cri-o.ImageName",
        ],
    );
    if ann["io.kubernetes.cri.container-type"] == "sandbox"
        || ann["io.kubernetes.cri-o.ContainerType"] == "sandbox"
    {
        meta.flags |= SANDBOX;
    }
    let bounding = spec["process"]["capabilities"]["bounding"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if bounding.iter().any(|c| c == "CAP_SYS_ADMIN") {
        meta.flags |= PRIVILEGED;
    }
    let namespaces: Vec<String> = spec["linux"]["namespaces"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|n| text(&n["type"]))
        .collect();
    if !namespaces.iter().any(|n| n == "pid") {
        meta.flags |= HOST_PID;
    }
    if !namespaces.iter().any(|n| n == "network") {
        meta.flags |= HOST_NET;
    }
}
