use alloy_sol_types::{Error, SolType};
use zkemail_core::{
    EmailVerifierOutput, SolEmailOutput, SolEmailWithRegexOutput, VerificationOutput,
};

pub trait AbiDecodable {
    fn abi_decode(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
}

impl AbiDecodable for VerificationOutput {
    fn abi_decode(data: &[u8]) -> Result<Self, Error> {
        if let Ok(email) = SolEmailOutput::abi_decode(data, true) {
            return Ok(Self::EmailOnly(EmailVerifierOutput {
                from_domain_hash: email.from_domain_hash.to_vec(),
                public_key_hash: email.public_key_hash.to_vec(),
                external_inputs: email.external_inputs.clone(),
            }));
        }

        let regex = SolEmailWithRegexOutput::abi_decode(data, true)?;
        Ok(Self::WithRegex {
            email: EmailVerifierOutput {
                from_domain_hash: regex.email.from_domain_hash.to_vec(),
                public_key_hash: regex.email.public_key_hash.to_vec(),
                external_inputs: regex.email.external_inputs.clone(),
            },
            matches: regex.matches,
        })
    }
}
