use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cfdkim::{dns::from_tokio_resolver, public_key::retrieve_public_key};
use chrono::{DateTime, Utc};
use reqwest::Client;
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::DecodePublicKey, RsaPublicKey};
use serde::Deserialize;
use slog::Logger;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

const ARCHIVE_API: &str = "https://archive.prove.email/api";

#[derive(Debug, Deserialize)]
struct DkimKeyResponse {
    value: String,
    selector: String,
    #[serde(rename = "firstSeenAt")]
    _first_seen_at: DateTime<Utc>,
    #[serde(rename = "lastSeenAt")]
    _last_seen_at: DateTime<Utc>,
}

fn convert_to_pkcs1(key_b64: &str) -> Result<Vec<u8>> {
    let pkcs8_der = STANDARD.decode(key_b64)?;
    RsaPublicKey::from_public_key_der(&pkcs8_der)?
        .to_pkcs1_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(Into::into)
}

pub async fn fetch_dkim_key(
    logger: &Logger,
    domain: &str,
    selector: &str,
) -> Result<(Vec<u8>, String)> {
    // Try DNS first
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["8.8.8.8".parse()?], 53, true),
        ),
        ResolverOpts::default(),
    );
    let resolver = from_tokio_resolver(resolver);

    match retrieve_public_key(logger, resolver, domain.to_string(), selector.to_string()).await {
        Ok(public_key) => Ok((public_key.to_vec(), public_key.key_type().to_string())),
        Err(_) => {
            // Fallback to archive
            let keys: Vec<DkimKeyResponse> = Client::new()
                .get(format!("{}/key?domain={}", ARCHIVE_API, domain))
                .send()
                .await?
                .json()
                .await?;

            let key = keys
                .iter()
                .find(|k| {
                    k.selector == selector && k.value.contains("p=") && !k.value.ends_with("p=")
                })
                .ok_or_else(|| anyhow!("No valid DKIM key found"))?;

            let (key_type, public_key) = key.value.split(';').map(str::trim).fold(
                (String::new(), String::new()),
                |(mut kt, mut pk), part| {
                    if let Some(stripped) = part.strip_prefix("k=") {
                        kt = stripped.to_string();
                    }
                    if let Some(stripped) = part.strip_prefix("p=") {
                        pk = stripped.to_string();
                    }
                    (kt, pk)
                },
            );

            if public_key.is_empty() {
                return Err(anyhow!("No public key found"));
            }

            let key_bytes = if key_type == "rsa" {
                convert_to_pkcs1(&public_key)?
            } else {
                STANDARD.decode(&public_key)?
            };

            Ok((key_bytes, key_type))
        }
    }
}
