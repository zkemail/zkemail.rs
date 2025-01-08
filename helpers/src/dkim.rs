use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::Client;
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::DecodePublicKey, RsaPublicKey};
use serde::Deserialize;

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

pub async fn fetch_dkim_key(domain: &str, selector: &str) -> Result<(Vec<u8>, String)> {
    let keys: Vec<DkimKeyResponse> = Client::new()
        .get(format!("{}/key?domain={}", ARCHIVE_API, domain))
        .send()
        .await?
        .json()
        .await?;

    let key = keys
        .iter()
        .find(|k| k.selector == selector && k.value.contains("p=") && !k.value.ends_with("p="))
        .ok_or_else(|| anyhow!("No valid DKIM key found for selector: {}", selector))?;

    let (key_type, public_key) = key.value.split(';').map(str::trim).fold(
        (String::new(), String::new()),
        |(mut kt, mut pk), part| {
            if part.starts_with("k=") {
                kt = part[2..].to_string();
            }
            if part.starts_with("p=") {
                pk = part[2..].to_string();
            }
            (kt, pk)
        },
    );

    if public_key.is_empty() {
        return Err(anyhow!("No public key found in DKIM record"));
    }

    let key_bytes = if key_type == "rsa" {
        convert_to_pkcs1(&public_key)?
    } else {
        STANDARD.decode(&public_key)?
    };

    Ok((key_bytes, key_type))
}
