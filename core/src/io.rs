use alloy_sol_types::{sol, SolValue};

use crate::EmailVerifierOutput;

sol!(
    struct SolEmailOutput {
        bytes32 from_domain_hash;
        bytes32 public_key_hash;
        string[] external_inputs; // [name1, value1, name2, value2, ...]
    }

    struct SolEmailWithRegexOutput {
        SolEmailOutput email;
        string[] matches;
    }
);

#[derive(Debug)]
pub enum VerificationOutput {
    EmailOnly(EmailVerifierOutput),
    WithRegex {
        email: EmailVerifierOutput,
        matches: Vec<String>,
    },
}

impl VerificationOutput {
    pub fn from_parts(email: EmailVerifierOutput, matches: Option<Vec<String>>) -> Self {
        match matches {
            None => Self::EmailOnly(email),
            Some(m) => Self::WithRegex { email, matches: m },
        }
    }

    pub fn abi_encode(&self) -> Vec<u8> {
        match self {
            Self::EmailOnly(email) => SolEmailOutput::abi_encode(&convert_email(email)),
            Self::WithRegex { email, matches } => (SolEmailWithRegexOutput {
                email: convert_email(email),
                matches: matches.clone(),
            })
            .abi_encode(),
        }
    }
}

fn convert_email(email: &EmailVerifierOutput) -> SolEmailOutput {
    SolEmailOutput {
        from_domain_hash: email.from_domain_hash.as_slice().try_into().unwrap(),
        public_key_hash: email.public_key_hash.as_slice().try_into().unwrap(),
        external_inputs: email.external_inputs.clone(),
    }
}
