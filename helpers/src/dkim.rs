use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cfdkim::{dns::from_tokio_resolver, public_key::retrieve_public_key, DkimPublicKey};
use chrono::{DateTime, Utc};
use reqwest::Client;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    RsaPublicKey,
};
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
        Ok(public_key) => match public_key {
            DkimPublicKey::Rsa(rsa_key) => {
                let key_bytes = rsa_key.to_pkcs1_der()?.as_bytes().to_vec();
                Ok((key_bytes, "rsa".to_string()))
            }
            DkimPublicKey::Ed25519(ed_key) => {
                let key_bytes = ed_key.to_bytes().to_vec();
                Ok((key_bytes, "ed25519".to_string()))
            }
        },
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

            let (mut key_type, public_key) = key.value.split(';').map(str::trim).fold(
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

            // defaults to rsa if no key type is found
            if key_type.is_empty() {
                key_type = "rsa".to_string();
            }

            if public_key.is_empty() {
                return Err(anyhow!("No public key found"));
            }

            let key_bytes = if key_type == "rsa" {
                let decoded = STANDARD.decode(&public_key)?;
                RsaPublicKey::from_public_key_der(&decoded)
                    .or_else(|_| RsaPublicKey::from_pkcs1_der(&decoded))?
                    .to_pkcs1_der()?
                    .as_bytes()
                    .to_vec()
            } else if key_type == "ed25519" {
                let decoded = STANDARD.decode(&public_key)?;
                if decoded.len() != 32 {
                    return Err(anyhow!("Invalid Ed25519 key length"));
                }
                decoded
            } else {
                return Err(anyhow!("Unsupported key type: {}", key_type));
            };

            Ok((key_bytes, key_type))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slog::{o, Drain, Logger};

    fn create_logger() -> Logger {
        let drain = slog::Discard;
        let root = Logger::root(drain.fuse(), o!());
        root
    }

    #[tokio::test]
    async fn test_fetch_dkim_key_from_archive() {
        let logger = create_logger();
        let domain = "cryptoradar.com";
        let selector = "ez5fdfeqyxjjof6psrzjbiqfmtoen2xs";

        let result = fetch_dkim_key(&logger, domain, selector).await;
        assert!(result.is_ok(), "fetch_dkim_key should succeed, but got: {:?}", result.err());
        
        let (key_bytes, key_type) = result.unwrap();
        assert!(!key_bytes.is_empty(), "key bytes should not be empty");
        assert_eq!(key_type, "rsa", "key type should be rsa for cryptoradar");
    }
}
