#[cfg(feature = "risc0")]
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct PublicKey {
    pub key: Vec<u8>,
    pub key_type: String,
}

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct DFA {
    pub fwd: Vec<u8>,
    pub bwd: Vec<u8>,
}

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct CompiledRegex {
    pub verify_re: DFA,
    pub capture_str: Option<String>,
}

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct RegexInfo {
    pub header_parts: Vec<CompiledRegex>,
    pub body_parts: Vec<CompiledRegex>,
}

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Email {
    pub from_domain: String,
    pub raw_email: Vec<u8>,
    pub public_key: PublicKey,
}

#[cfg_attr(feature = "risc0", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "sp1", derive(Serialize, Deserialize))]
#[derive(Debug)]
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
