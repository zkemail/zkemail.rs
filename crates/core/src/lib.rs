use anyhow::Result;
use base64::prelude::*;
use sha2::{ Digest, Sha256 };

use rsa::{ pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey };

pub struct EmailVerifier {
    headers: Vec<u8>,
    body: Vec<u8>,
    signature: Vec<u8>,
    body_hash: String,
    public_key: RsaPublicKey,
}

impl EmailVerifier {
    pub fn new(
        headers: Vec<u8>,
        body: Vec<u8>,
        signature: Vec<u8>,
        body_hash: String,
        public_key_pem: &str
    ) -> Result<Self> {
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)?;

        Ok(Self {
            headers,
            body,
            signature,
            body_hash,
            public_key,
        })
    }

    pub fn from_eml(eml_content: &str, public_key_pem: &str) -> Result<Self> {
        todo!()
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(&self.headers);
        let hash = hasher.finalize();

        let padding = Pkcs1v15Sign {
            hash_len: Some(32),
            prefix: Box::new([
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ]),
        };
        Ok(self.public_key.verify(padding, &hash, &self.signature).is_ok())
    }

    pub fn verify_body(&self) -> Result<bool> {
        let mut hasher = Sha256::new();
        hasher.update(&self.body);
        let hash = hasher.finalize();

        let computed_hash = BASE64_STANDARD.encode(hash);
        Ok(computed_hash == self.body_hash)
    }
}
