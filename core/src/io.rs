use alloy_sol_types::{sol, SolType};

use crate::{EmailVerifierOutput, EmailWithRegexVerifierOutput};

sol!(
    struct SolEmailVerifierOutput {
        bytes32 from_domain_hash;
        bytes32 public_key_hash;
        bool verified;
    }

    struct SolEmailWithRegexVerifierOutput {
        SolEmailVerifierOutput email;
        bool header_regex_verified;
        bool body_regex_verified;
        string[] header_regex_matches;
        string[] body_regex_matches;
    }
);

pub fn abi_encode_email_verifier_output(output: &EmailVerifierOutput) -> Vec<u8> {
    SolEmailVerifierOutput::abi_encode(
        &(SolEmailVerifierOutput {
            from_domain_hash: output.from_domain_hash.as_slice().try_into().unwrap(),
            public_key_hash: output.public_key_hash.as_slice().try_into().unwrap(),
            verified: output.verified,
        }),
    )
}

pub fn abi_encode_email_with_regex_verifier_output(
    output: &EmailWithRegexVerifierOutput,
) -> Vec<u8> {
    SolEmailWithRegexVerifierOutput::abi_encode(
        &(SolEmailWithRegexVerifierOutput {
            email: SolEmailVerifierOutput {
                from_domain_hash: output.email.from_domain_hash.as_slice().try_into().unwrap(),
                public_key_hash: output.email.public_key_hash.as_slice().try_into().unwrap(),
                verified: output.email.verified,
            },
            header_regex_verified: output.header_regex_verified,
            body_regex_verified: output.body_regex_verified,
            header_regex_matches: output
                .header_regex_matches
                .iter()
                .map(|s| s.to_string())
                .collect(),
            body_regex_matches: output
                .body_regex_matches
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }),
    )
}
