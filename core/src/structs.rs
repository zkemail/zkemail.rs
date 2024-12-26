use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub key: Vec<u8>,
    pub key_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DFA {
    pub fwd: Vec<u8>,
    pub bwd: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompiledRegex {
    pub verify_re: DFA,
    pub capture_str: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexInfo {
    pub header_parts: Vec<CompiledRegex>,
    pub body_parts: Vec<CompiledRegex>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub from_domain: String,
    pub raw_email: Vec<u8>,
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailWithRegex {
    pub email: Email,
    pub regex_info: RegexInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailVerifierOutput {
    pub from_domain_hash: Vec<u8>,
    pub public_key_hash: Vec<u8>,
    pub verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailWithRegexVerifierOutput {
    pub email: EmailVerifierOutput,
    pub header_regex_verified: bool,
    pub body_regex_verified: bool,
    pub header_regex_matches: Vec<String>,
    pub body_regex_matches: Vec<String>,
}
