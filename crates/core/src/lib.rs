//! DKIM email verification implementation.
//! This module provides functionality to verify DKIM signatures in email messages.

pub mod dns_resolver;

use anyhow::{Context, Result};
use base64::prelude::*;
use cfdkim::canonicalize_signed_email;
use dns_resolver::DkimResolver;
use mail_parser::{HeaderValue, MessageParser};
use regex_automata::{dfa::dense, Match};
use rsa::{pkcs8::DecodePublicKey, signature::digest::Digest, Pkcs1v15Sign, RsaPublicKey};
use sha2::Sha256;
use std::{collections::HashMap, str};

/// RSA-SHA256 signature prefix for PKCS#1 v1.5 padding
const RSA_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Represents a DKIM email verifier that can validate signatures and body hashes
#[derive(Debug)]
pub struct EmailVerifier {
    canonicalized_header: Vec<u8>,
    canonicalized_body: Vec<u8>,
    signature: Vec<u8>,
    dkim_fields: HashMap<String, String>,
    public_key: RsaPublicKey,
}

impl EmailVerifier {
    /// Creates a new EmailVerifier from raw email content
    ///
    /// # Arguments
    /// * `eml_content` - Raw email content as bytes
    ///
    /// # Returns
    /// * `Result<EmailVerifier>` - Initialized verifier or error
    ///
    /// # Errors
    /// * When email parsing fails
    /// * When DKIM signature is missing or invalid
    /// * When public key retrieval fails
    pub async fn from_eml(eml_content: &[u8]) -> Result<Self> {
        // Canonicalize email parts using cfdkim
        let (canonicalized_header, canonicalized_body, signature) =
            canonicalize_signed_email(eml_content).context("Failed to canonicalize email")?;

        // Parse email for DKIM fields
        let dkim_fields = Self::extract_dkim_fields(eml_content)?;

        // Fetch and parse public key
        let public_key = Self::fetch_public_key(&dkim_fields).await?;

        Ok(Self {
            canonicalized_header,
            canonicalized_body,
            signature,
            dkim_fields,
            public_key,
        })
    }

    /// Verifies the DKIM signature using the canonicalized header and public key
    ///
    /// # Returns
    /// * `Result<bool>` - True if signature is valid, false otherwise
    pub fn verify_signature(&self) -> Result<bool> {
        let hash = Self::calculate_sha256(&self.canonicalized_header);

        let padding = Pkcs1v15Sign {
            hash_len: Some(32),
            prefix: Box::new(RSA_SHA256_PREFIX),
        };

        Ok(self
            .public_key
            .verify(padding, &hash, &self.signature)
            .is_ok())
    }

    /// Verifies the email body hash against the one in DKIM signature
    ///
    /// # Returns
    /// * `Result<bool>` - True if body hash matches, false otherwise
    pub fn verify_body(&self) -> Result<bool> {
        let hash = Self::calculate_sha256(&self.canonicalized_body);
        let computed_hash = BASE64_STANDARD.encode(hash);

        let body_hash = self
            .dkim_fields
            .get("bh")
            .context("Missing body hash in DKIM fields")?
            .trim_matches('"');

        Ok(computed_hash == body_hash)
    }

    /// ZkVM-friendly pattern matching using pre-compiled DFAs
    ///
    /// # Arguments
    /// * `dfa_fwd` - Forward DFA bytes in little-endian format
    /// * `dfa_rev` - Reverse DFA bytes in little-endian format
    /// * `in_headers` - Whether to search in headers (true) or body (false)
    /// * `reveal` - Whether to return the matched content
    ///
    /// # Returns
    /// * `Result<Option<String>>` - Matched text if found and reveal=true
    pub fn verify_pattern(
        &self,
        dfa_fwd: &[u8],
        dfa_rev: &[u8],
        in_headers: bool,
        reveal: bool,
    ) -> Result<Option<String>> {
        let fwd: dense::DFA<&[u32]> = dense::DFA::from_bytes(dfa_fwd)
            .context("Failed to load forward DFA")?
            .0;
        let rev: dense::DFA<&[u32]> = dense::DFA::from_bytes(dfa_rev)
            .context("Failed to load reverse DFA")?
            .0;

        let re = regex_automata::dfa::regex::Regex::builder().build_from_dfas(fwd, rev);

        let text = if in_headers {
            &self.canonicalized_header
        } else {
            &self.canonicalized_body
        };
        let matches: Vec<Match> = re.find_iter(text).collect();

        if !matches.is_empty() {
            if reveal {
                let m = matches[0];
                let matched = &text[m.start()..m.end()];
                String::from_utf8(matched.to_vec())
                    .context("Invalid UTF-8 in matched text")
                    .map(Some)
            } else {
                Ok(Some("Pattern found but not revealed".to_string()))
            }
        } else {
            Ok(None)
        }
    }

    // Private helper methods
    fn extract_dkim_fields(eml_content: &[u8]) -> Result<HashMap<String, String>> {
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

    async fn fetch_public_key(dkim_fields: &HashMap<String, String>) -> Result<RsaPublicKey> {
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

    fn calculate_sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex_automata::dfa::regex::Regex as DfaRegex;
    use std::fs;

    #[tokio::test]
    async fn test_verify_email() -> Result<()> {
        let eml_content =
            fs::read("./test_emails/test.eml").context("Failed to read test email")?;
        let verifier = EmailVerifier::from_eml(&eml_content).await?;

        assert!(
            verifier.verify_signature()?,
            "Signature verification failed"
        );
        assert!(verifier.verify_body()?, "Body verification failed");

        Ok(())
    }

    #[tokio::test]
    async fn test_pattern() -> Result<()> {
        let eml_content =
            fs::read("./test_emails/test.eml").context("Failed to read test email")?;
        let verifier = EmailVerifier::from_eml(&eml_content).await?;

        // Test for reset code
        let pattern = r"t7bezzrn"; // The actual reset code from the email
        let dfa = DfaRegex::new(pattern)?;
        let fwd_bytes = dfa.forward().to_bytes_native_endian().0;
        let rev_bytes = dfa.reverse().to_bytes_native_endian().0;

        let result = verifier.verify_pattern(
            &fwd_bytes, &rev_bytes, false, // search in body
            true,  // reveal match
        )?;

        assert!(result.is_some(), "Reset code should be found");
        assert_eq!(result.unwrap(), "t7bezzrn", "Should match exact reset code");

        // Test for username
        let pattern = r"@0xDMello"; // The username from the email
        let dfa = DfaRegex::new(pattern)?;
        let fwd_bytes = dfa.forward().to_bytes_native_endian().0;
        let rev_bytes = dfa.reverse().to_bytes_native_endian().0;

        let result = verifier.verify_pattern(
            &fwd_bytes, &rev_bytes, false, // search in body
            true,  // reveal match
        )?;

        assert!(result.is_some(), "Username should be found");
        assert_eq!(result.unwrap(), "@0xDMello", "Should match exact username");

        Ok(())
    }
}
