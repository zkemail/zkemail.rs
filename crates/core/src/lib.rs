use base64::prelude::*;
use rsa::{ pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey };
use sha2::{ Digest, Sha256 };
use thiserror::Error;
use regex::Regex;
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use mail_parser::Message;

#[derive(Serialize, Deserialize, Debug)]
pub struct DKIMData {
    pub public_key: String,
    pub signature: String,
    pub headers: String,
    pub body: String,
    pub body_hash: String,
    pub signing_domain: String,
    pub selector: String,
    pub algo: String,
    pub format: String,
}

pub struct EmailVerifier {
    dkim: DKIMData,
}

impl EmailVerifier {
    pub fn new(dkim: DKIMData) -> Self {
        Self { dkim }
    }

    /// Create EmailVerifier from an .eml file and public key
    pub fn from_eml(eml_content: &str, public_key: String) -> Result<Self> {
        let email = Message::parse(eml_content.as_bytes()).ok_or_else(||
            EmailVerificationError::ParseError("Failed to parse email".into())
        )?;

        // Extract DKIM-Signature header
        let dkim_header = email
            .headers()
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case("DKIM-Signature"))
            .ok_or_else(|| EmailVerificationError::ParseError("No DKIM signature found".into()))?;

        // Parse DKIM fields
        let dkim_fields: HashMap<&str, &str> = dkim_header
            .value_raw()
            .split(';')
            .filter_map(|field| {
                let parts: Vec<&str> = field.trim().splitn(2, '=').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim(), parts[1].trim()))
                } else {
                    None
                }
            })
            .collect();

        // Extract required fields
        let signature = dkim_fields
            .get("b")
            .ok_or_else(|| EmailVerificationError::ParseError("No signature found".into()))?
            .to_string();

        let body_hash = dkim_fields
            .get("bh")
            .ok_or_else(|| EmailVerificationError::ParseError("No body hash found".into()))?
            .to_string();

        let signing_domain = dkim_fields
            .get("d")
            .ok_or_else(|| EmailVerificationError::ParseError("No domain found".into()))?
            .to_string();

        let selector = dkim_fields
            .get("s")
            .ok_or_else(|| EmailVerificationError::ParseError("No selector found".into()))?
            .to_string();

        let algo = dkim_fields
            .get("a")
            .ok_or_else(|| EmailVerificationError::ParseError("No algorithm found".into()))?
            .to_string();

        // Get canonicalized headers and body
        let headers = email.raw_headers().to_string();
        let body = email.raw_body().unwrap_or_default().to_string();

        let dkim = DKIMData {
            public_key,
            signature,
            headers,
            body,
            body_hash,
            signing_domain,
            selector,
            algo,
            format: "relaxed/relaxed".to_string(), // Default canonicalization
        };

        Ok(Self::new(dkim))
    }

    /// Verify the DKIM signature
    pub fn verify_signature(&self) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(self.dkim.headers.as_bytes());
        let hash = hasher.finalize();

        let public_key = RsaPublicKey::from_public_key_pem(&self.dkim.public_key)?;

        let signature = BASE64_STANDARD.decode(&self.dkim.signature)?;

        // RSASSA-PKCS1-V1_5 padding bytes
        let prefix: Box<[u8]> = Box::new([
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ]);

        let padding = Pkcs1v15Sign {
            hash_len: Some(32),
            prefix,
        };

        match public_key.verify(padding, &hash, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Err(EmailVerificationError::InvalidSignature),
        }
    }

    /// Verify the email body hash matches the signed hash
    pub fn verify_body(&self) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(self.dkim.body.as_bytes());
        let hash = hasher.finalize();

        let base64_hash = BASE64_STANDARD.encode(&hash);

        if base64_hash != self.dkim.body_hash {
            Err(EmailVerificationError::InvalidBodyHash)
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add tests here
}
