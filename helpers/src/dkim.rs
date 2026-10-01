use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cfdkim::{dns::from_tokio_resolver, public_key::retrieve_public_key, DkimPublicKey};
use reqwest::{Client, StatusCode};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    RsaPublicKey,
};
use serde::Deserialize;
use slog::Logger;
use std::time::Duration;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

const ARCHIVE_API: &str = "https://archive.prove.email/api";

// NOTE: archive.prove.email allows 10 requests/min per IP. A 429 is retried once after the
// server's retryAfterSeconds, but only if that is short; a longer wait would stall the caller.
const MAX_ARCHIVE_RETRY_WAIT_SECS: u64 = 15;

#[derive(Debug, Deserialize)]
struct DkimKeyResponse {
    value: String,
    selector: String,
    // NOTE: only used to order candidates; optional so a record without it still parses.
    #[serde(rename = "lastSeenAt", default)]
    last_seen_at: Option<String>,
}

/// A DKIM public key that may have signed a message, with where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKeyCandidate {
    pub key: Vec<u8>,
    pub key_type: String,
    /// "dns" or "archive"
    pub source: &'static str,
}

/// Every plausible key for `selector._domainkey.domain`: the current DNS key, then every key
/// the archive has seen for that selector (most recently seen first), deduplicated.
///
/// REASON: the old lookup used the archive only when DNS *failed*, and then only its first
/// record for the selector. Both miss common cases: a sender that rotated the key but kept
/// the selector (DNS answers with the new key, so the old signing key is never tried), and
/// selectors with several archived keys where the signing key isn't the first record. Trying
/// more keys can't make a forged signature verify: each key is checked against the signature.
pub async fn fetch_dkim_key_candidates(
    logger: &Logger,
    domain: &str,
    selector: &str,
) -> Result<Vec<DkimKeyCandidate>> {
    let mut candidates = Vec::new();
    let mut errors = Vec::new();

    match fetch_dns_key(logger, domain, selector).await {
        Ok(c) => candidates.push(c),
        Err(e) => errors.push(format!("dns: {e}")),
    }
    match fetch_archive_keys(&Client::new(), ARCHIVE_API, domain, selector).await {
        Ok(keys) => {
            for c in keys {
                if !candidates.iter().any(|k| k.key == c.key) {
                    candidates.push(c);
                }
            }
        }
        Err(e) => errors.push(format!("archive: {e}")),
    }

    if candidates.is_empty() {
        return Err(anyhow!(
            "No DKIM key found for {selector}._domainkey.{domain} ({})",
            errors.join("; ")
        ));
    }
    Ok(candidates)
}

async fn fetch_dns_key(logger: &Logger, domain: &str, selector: &str) -> Result<DkimKeyCandidate> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["8.8.8.8".parse()?], 53, true),
        ),
        ResolverOpts::default(),
    );
    let resolver = from_tokio_resolver(resolver);

    let (key, key_type) =
        match retrieve_public_key(logger, resolver, domain.to_string(), selector.to_string())
            .await?
        {
            DkimPublicKey::Rsa(rsa_key) => {
                (rsa_key.to_pkcs1_der()?.as_bytes().to_vec(), "rsa".to_string())
            }
            DkimPublicKey::Ed25519(ed_key) => (ed_key.to_bytes().to_vec(), "ed25519".to_string()),
        };
    Ok(DkimKeyCandidate {
        key,
        key_type,
        source: "dns",
    })
}

/// Archived keys for `selector` at `domain`, most recently seen first.
pub(crate) async fn fetch_archive_keys(
    client: &Client,
    api_base: &str,
    domain: &str,
    selector: &str,
) -> Result<Vec<DkimKeyCandidate>> {
    let url = format!("{api_base}/key");
    let mut attempt = 0;
    let body = loop {
        let resp = client
            .get(&url)
            .query(&[("domain", domain)])
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status.is_success() {
            break text;
        }
        // NOTE: on 429 the archive answers with a JSON error object (not an array), which
        // previously surfaced as a confusing deserialization error.
        if status == StatusCode::TOO_MANY_REQUESTS {
            let wait = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.pointer("/details/retryAfterSeconds")?.as_u64());
            if attempt == 0 {
                if let Some(wait) = wait.filter(|w| *w <= MAX_ARCHIVE_RETRY_WAIT_SECS) {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_secs(wait)).await;
                    continue;
                }
            }
            return Err(anyhow!(
                "archive.prove.email rate limit (10 requests/min per IP); retry in a minute"
            ));
        }
        return Err(anyhow!("archive.prove.email HTTP {status}"));
    };

    let mut records: Vec<DkimKeyResponse> = serde_json::from_str(&body)?;
    records.retain(|r| r.selector == selector);
    // ISO-8601 timestamps sort lexicographically; records without one go last.
    records.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));

    let mut out: Vec<DkimKeyCandidate> = Vec::new();
    for r in records {
        // NOTE: a malformed or revoked (empty p=) record must not hide the other records.
        if let Ok(c) = parse_dkim_record(&r.value) {
            if !out.iter().any(|k| k.key == c.key) {
                out.push(c);
            }
        }
    }
    Ok(out)
}

/// Key bytes (PKCS#1 DER for RSA, raw 32 bytes for ed25519) from a "v=DKIM1; k=..; p=.." record.
fn parse_dkim_record(record: &str) -> Result<DkimKeyCandidate> {
    let mut key_type = String::new();
    let mut public_key = String::new();
    for part in record.split(';') {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        // RFC 6376 tag values may contain folding whitespace; it is not part of the value.
        let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        match name.trim() {
            "k" => key_type = value,
            "p" => public_key = value,
            _ => {}
        }
    }
    if key_type.is_empty() {
        key_type = "rsa".to_string();
    }
    if public_key.is_empty() {
        return Err(anyhow!("No public key found (revoked or missing p=)"));
    }
    let decoded = STANDARD.decode(&public_key)?;
    let key = match key_type.as_str() {
        "rsa" => RsaPublicKey::from_public_key_der(&decoded)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(&decoded))?
            .to_pkcs1_der()?
            .as_bytes()
            .to_vec(),
        "ed25519" => {
            if decoded.len() != 32 {
                return Err(anyhow!("Invalid Ed25519 key length"));
            }
            decoded
        }
        other => return Err(anyhow!("Unsupported key type: {other}")),
    };
    Ok(DkimKeyCandidate {
        key,
        key_type,
        source: "archive",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};

    fn rsa_record(key: &RsaPrivateKey) -> String {
        let der = key.to_public_key().to_public_key_der().unwrap();
        format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(der.as_bytes()))
    }

    fn pkcs1(key: &RsaPrivateKey) -> Vec<u8> {
        key.to_public_key().to_pkcs1_der().unwrap().as_bytes().to_vec()
    }

    #[tokio::test]
    async fn archive_returns_every_key_for_the_selector_newest_first() {
        let mut rng = rand::thread_rng();
        let old = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let new = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let other = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        // Folded p= value (whitespace inside the base64) must still parse.
        let folded_new = rsa_record(&new).replacen("p=", "p= ", 1);
        let body = serde_json::json!([
            {"selector": "s1", "value": rsa_record(&old), "lastSeenAt": "2023-01-01T00:00:00.000Z"},
            {"selector": "s2", "value": rsa_record(&other), "lastSeenAt": "2025-01-01T00:00:00.000Z"},
            {"selector": "s1", "value": "v=DKIM1; k=rsa; p=", "lastSeenAt": "2026-01-01T00:00:00.000Z"},
            {"selector": "s1", "value": folded_new, "lastSeenAt": "2024-06-01T00:00:00.000Z"},
            {"selector": "s1", "value": rsa_record(&old), "lastSeenAt": "2022-01-01T00:00:00.000Z"}
        ]);
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/key").query_param("domain", "example.com");
            then.status(200).json_body(body);
        });

        let keys = fetch_archive_keys(&Client::new(), &server.base_url(), "example.com", "s1")
            .await
            .unwrap();
        // revoked record dropped, other selector filtered, duplicate removed, newest first
        assert_eq!(
            keys.iter().map(|k| k.key.clone()).collect::<Vec<_>>(),
            vec![pkcs1(&new), pkcs1(&old)]
        );
        assert!(keys.iter().all(|k| k.source == "archive" && k.key_type == "rsa"));
    }

    #[tokio::test]
    async fn archive_rate_limit_is_reported_not_a_parse_error() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/key");
            then.status(429).json_body(serde_json::json!({
                "error": "Too many requests",
                "details": {"retryAfterSeconds": 1}
            }));
        });
        let err = fetch_archive_keys(&Client::new(), &server.base_url(), "example.com", "s1")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{err}");
        // one retry after retryAfterSeconds, then give up
        mock.assert_hits(2);
    }

    #[tokio::test]
    async fn archive_rate_limit_with_long_wait_is_not_retried() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/key");
            then.status(429).json_body(serde_json::json!({
                "details": {"retryAfterSeconds": 3600}
            }));
        });
        assert!(
            fetch_archive_keys(&Client::new(), &server.base_url(), "example.com", "s1")
                .await
                .is_err()
        );
        mock.assert_hits(1);
    }
}
