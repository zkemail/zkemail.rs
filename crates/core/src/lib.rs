//! DKIM email verification implementation.
//! This module provides functionality to verify DKIM signatures in email messages.

pub mod dns_resolver;
pub mod email_parser;
pub mod utils;

use anyhow::{Context, Result};
use base64::prelude::*;
use regex::Regex;
use regex_automata::dfa::dense;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use utils::calculate_sha256;

/// RSA-SHA256 signature prefix for PKCS#1 v1.5 padding
const RSA_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub fn verify_signature(
    header: &[u8],
    signature: &[u8],
    public_key: &RsaPublicKey,
) -> Result<bool> {
    let hash = calculate_sha256(header);
    let padding = Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: Box::new(RSA_SHA256_PREFIX),
    };

    Ok(public_key.verify(padding, &hash, signature).is_ok())
}

pub fn extract_body_hash_from_header_dfa(
    header: &[u8],
    dfa_fwd: &[u8],
    dfa_rev: &[u8],
) -> Result<String> {
    let fwd = dense::DFA::from_bytes(dfa_fwd)?.0;
    let rev = dense::DFA::from_bytes(dfa_rev)?.0;

    let re = regex_automata::dfa::regex::Regex::builder().build_from_dfas(fwd, rev);

    let matched = re
        .find_iter(header)
        .next()
        .context("No body hash found in header")?;

    let matched_text = &header[matched.start()..matched.end()];
    let body_hash = String::from_utf8_lossy(matched_text)
        .trim_start_matches("bh=")
        .trim_end_matches(|c| (c == ';' || c == ' '))
        .to_string();

    Ok(body_hash)
}

pub fn extract_body_hash_from_header_regex(header: &[u8]) -> Result<String> {
    let header_str = String::from_utf8(header.to_vec())?;
    let re = Regex::new(r"bh=([A-Za-z0-9+/=]+)[;\s]")?;

    let captures = re
        .captures(&header_str)
        .context("No body hash found in header")?;

    Ok(captures[1].to_string())
}

pub fn verify_body(body: &[u8], body_hash: &str) -> Result<bool> {
    let hash = calculate_sha256(body);
    let computed_hash = BASE64_STANDARD.encode(hash);
    Ok(computed_hash == body_hash)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use regex_automata::dfa::regex::Regex;
    use std::fs;

    use crate::{
        email_parser::parse_dkim_components, extract_body_hash_from_header_dfa,
        extract_body_hash_from_header_regex, verify_body, verify_signature,
    };

    #[tokio::test]
    async fn test_email_verification() -> Result<()> {
        let email_content = fs::read("test_emails/test.eml")?;

        let (public_key, signature, header, body, _) =
            parse_dkim_components(&email_content).await?;

        let verified = verify_signature(&header, &signature, &public_key)?;
        assert!(verified);

        let re = Regex::new(r"bh=([A-Za-z0-9+/=]+)[;\s]")?;
        let (fwd_bytes, fwd_pad) = re.forward().to_bytes_little_endian();
        let (rev_bytes, rev_pad) = re.reverse().to_bytes_little_endian();
        let fwd_bytes = &fwd_bytes[fwd_pad..];
        let rev_bytes = &rev_bytes[rev_pad..];

        let body_hash_dfa = extract_body_hash_from_header_dfa(&header, fwd_bytes, rev_bytes)?;
        let body_hash_regex = extract_body_hash_from_header_regex(&header)?;
        assert_eq!(body_hash_dfa, body_hash_regex);

        let verified_body = verify_body(&body, &body_hash_regex)?;
        assert!(verified_body);

        Ok(())
    }
}
