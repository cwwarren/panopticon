use std::env;
use std::error::Error;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use ureq::Agent;

const TIMEOUT: Duration = Duration::from_secs(20);
// Instance-role credentials are replaced at least five minutes before they expire.
const REFRESH: Duration = Duration::from_secs(300);

pub struct Store {
    agent: Agent,
    imds: Agent,
    endpoint: String,
    host: String,
    bucket: String,
    prefix: String,
    region: String,
    creds: Creds,
}

enum Creds {
    Env(Keys),
    Instance {
        base: String,
        cache: Mutex<Option<(Keys, Instant)>>,
    },
}

#[derive(Clone)]
struct Keys {
    id: String,
    secret: String,
    token: Option<String>,
}

impl Store {
    pub fn new(dest: &str) -> Self {
        let rest = dest
            .strip_prefix("s3://")
            .unwrap_or_else(|| panic!("{dest}: expected s3://<bucket>[/<prefix>]"));
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let prefix = prefix.trim_matches('/');
        assert!(
            !bucket.is_empty()
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
            "{dest}: bucket required; prefix limited to letters, digits and /._-"
        );
        let region = env::var("AWS_REGION").expect("AWS_REGION is not set");
        let endpoint = env::var("AWS_ENDPOINT_URL_S3")
            .unwrap_or_else(|_| format!("https://s3.{region}.amazonaws.com"))
            .trim_end_matches('/')
            .to_string();
        let host = endpoint
            .split_once("://")
            .map(|(_, host)| host.to_string())
            .unwrap_or_else(|| panic!("{endpoint}: expected a URL"));
        let creds = match (
            env::var("AWS_ACCESS_KEY_ID"),
            env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            (Ok(id), Ok(secret)) => Creds::Env(Keys {
                id,
                secret,
                token: env::var("AWS_SESSION_TOKEN").ok(),
            }),
            _ => Creds::Instance {
                base: env::var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                    .unwrap_or_else(|_| "http://169.254.169.254".to_string())
                    .trim_end_matches('/')
                    .to_string(),
                cache: Mutex::new(None),
            },
        };
        let agent = Agent::config_builder()
            .timeout_connect(Some(TIMEOUT))
            .timeout_per_read(Some(TIMEOUT))
            .timeout_per_write(Some(TIMEOUT))
            .http_status_as_error(false)
            .build()
            .new_agent();
        let imds = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .new_agent();
        Store {
            agent,
            imds,
            endpoint,
            host,
            bucket: bucket.to_string(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
            region,
            creds,
        }
    }

    // 200 once S3 holds the batch, including when an earlier attempt stored it (412 on the
    // conditional write, which also keeps a batch from ever being replaced); 503 asks the agent
    // to retry.
    pub fn put(&self, host: &str, run: u64, seq: u64, body: &[u8]) -> u16 {
        let key = format!("{}{host}/{run:020}/{seq:010}.jsonl.gz", self.prefix);
        match self.try_put(&key, body) {
            Ok(200 | 412) => 200,
            Ok(status) => {
                eprintln!("s3 {key}: HTTP {status}");
                503
            }
            Err(err) => {
                eprintln!("s3 {key}: {err}");
                503
            }
        }
    }

    fn try_put(&self, key: &str, body: &[u8]) -> Result<u16, Box<dyn Error>> {
        let keys = self.keys()?;
        let path = format!("/{}/{key}", self.bucket);
        let hash = hex(&Sha256::digest(body));
        let (date, stamp) = amz_time(SystemTime::now());
        let mut headers = vec![
            ("host", self.host.clone()),
            ("if-none-match", "*".to_string()),
            ("x-amz-content-sha256", hash.clone()),
            ("x-amz-date", stamp.clone()),
        ];
        if let Some(token) = &keys.token {
            headers.push(("x-amz-security-token", token.clone()));
        }
        let names = headers
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(";");
        let canonical: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let request = format!("PUT\n{path}\n\n{canonical}\n{names}\n{hash}");
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&Sha256::digest(request.as_bytes()))
        );
        let mut key = hmac(format!("AWS4{}", keys.secret).as_bytes(), date.as_bytes());
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={}",
            keys.id,
            hex(&hmac(&key, to_sign.as_bytes()))
        );
        let mut put = self
            .agent
            .put(format!("{}{path}", self.endpoint))
            .header("authorization", auth);
        for (name, value) in &headers[1..] {
            put = put.header(*name, value);
        }
        Ok(put.send(body)?.status().as_u16())
    }

    fn keys(&self) -> Result<Keys, Box<dyn Error>> {
        match &self.creds {
            Creds::Env(keys) => Ok(keys.clone()),
            Creds::Instance { base, cache } => {
                let mut cache = cache.lock().unwrap();
                if let Some((keys, at)) = &*cache
                    && at.elapsed() < REFRESH
                {
                    return Ok(keys.clone());
                }
                let keys = self.instance_keys(base)?;
                *cache = Some((keys.clone(), Instant::now()));
                Ok(keys)
            }
        }
    }

    // EC2 instance-role credentials through IMDSv2.
    fn instance_keys(&self, base: &str) -> Result<Keys, Box<dyn Error>> {
        let token = self
            .imds
            .put(format!("{base}/latest/api/token"))
            .header("x-aws-ec2-metadata-token-ttl-seconds", "60")
            .send_empty()?
            .body_mut()
            .read_to_string()?;
        let url = format!("{base}/latest/meta-data/iam/security-credentials/");
        let get = |url: &str| -> Result<String, ureq::Error> {
            self.imds
                .get(url)
                .header("x-aws-ec2-metadata-token", &token)
                .call()?
                .body_mut()
                .read_to_string()
        };
        let role = get(&url)?;
        let creds: serde_json::Value =
            serde_json::from_str(&get(&format!("{url}{}", role.trim()))?)?;
        let field = |name: &str| {
            creds[name]
                .as_str()
                .map(str::to_string)
                .ok_or(format!("IMDS credentials lack {name}"))
        };
        Ok(Keys {
            id: field("AccessKeyId")?,
            secret: field("SecretAccessKey")?,
            token: Some(field("Token")?),
        })
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn amz_time(now: SystemTime) -> (String, String) {
    let secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (y, m, d) = civil(i64::try_from(secs / 86_400).unwrap());
    let date = format!("{y:04}{m:02}{d:02}");
    let t = secs % 86_400;
    let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t / 60 % 60, t % 60);
    (date, stamp)
}

// Days since 1970-01-01 to (year, month, day): Howard Hinnant's civil_from_days.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}
