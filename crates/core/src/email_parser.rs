use crate::dns_resolver::DkimResolver;
use anyhow::{Context, Ok, Result};
use cfdkim::canonicalize_signed_email;
use mail_parser::{HeaderValue, MessageParser};
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};

use std::collections::HashMap;

pub fn extract_dkim_fields(eml_content: &[u8]) -> Result<HashMap<String, String>> {
    let message = MessageParser::default()
        .parse(eml_content)
        .context("Failed to parse email")?;

    let dkim_header = message
        .headers()
        .iter()
        .find(|h| h.name().eq("DKIM-Signature"))
        .context("DKIM-Signature header not found")?;

    let dkim_value = match dkim_header.value() {
        HeaderValue::Text(text) => text,
        _ => {
            return Err(anyhow::anyhow!("Invalid DKIM header value"));
        }
    };

    Ok(dkim_value
        .split(';')
        .filter_map(|field| {
            let parts: Vec<&str> = field.trim().splitn(2, '=').collect();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                None
            }
        })
        .collect())
}

pub async fn fetch_public_key(dkim_fields: &HashMap<String, String>) -> Result<RsaPublicKey> {
    let domain = dkim_fields
        .get("d")
        .context("Missing domain in DKIM fields")?
        .trim_matches('"');
    let selector = dkim_fields
        .get("s")
        .context("Missing selector in DKIM fields")?
        .trim_matches('"');

    let resolver = DkimResolver::new()?;
    let public_key_pem = resolver.fetch_dkim_key(selector, domain).await?;
    RsaPublicKey::from_public_key_pem(&public_key_pem).context("Failed to parse public key")
}

pub async fn parse_dkim_components(
    eml_content: &[u8],
) -> Result<(
    RsaPublicKey,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    HashMap<String, String>,
)> {
    // Canonicalize email parts using cfdkim
    let (header, body, signature) =
        canonicalize_signed_email(eml_content).context("Failed to canonicalize email")?;

    // Parse email for DKIM fields
    let dkim_fields = extract_dkim_fields(eml_content)?;

    // Fetch and parse public key
    let public_key = fetch_public_key(&dkim_fields).await?;

    Ok((public_key, signature, header, body, dkim_fields))
}
