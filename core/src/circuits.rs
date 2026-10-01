use slog::{o, Discard, Logger};

use crate::{
    canonicalize_verified_email, hash_bytes, process_regex_parts,
    remove_quoted_printable_soft_breaks, verify_dkim, Email,
    EmailVerifierOutput, EmailWithRegex, EmailWithRegexVerifierOutput,
};

pub fn verify_email(email: &Email) -> EmailVerifierOutput {
    let logger = Logger::root(Discard, o!());

    let verified = verify_dkim(email, &logger);
    assert!(verified);

    EmailVerifierOutput {
        from_domain_hash: hash_bytes(email.from_domain.as_bytes()),
        public_key_hash: hash_bytes(&email.public_key.key),
        external_inputs: email
            .external_inputs
            .iter()
            .flat_map(|inputs| {
                vec![
                    inputs.name.clone(),
                    inputs.value.clone().expect("Value cannot be null"),
                ]
            })
            .collect(),
    }
}

pub fn verify_email_with_regex(input: &EmailWithRegex) -> EmailWithRegexVerifierOutput {
    let logger = Logger::root(Discard, o!());
    let email_verifier_output = verify_email(&input.email);

    // REASON: the regexes must run over the header/body of the signature that verify_email
    // checked. cfdkim's canonicalize_signed_email canonicalizes the FIRST DKIM-Signature, which
    // need not be the verified one (several signatures on one message are common), and its h=
    // list can then pull in headers the verified signature does not cover.
    let (canonicalized_header, canonicalized_body) =
        canonicalize_verified_email(&input.email, &logger);

    let (cleaned_body, _) = remove_quoted_printable_soft_breaks(canonicalized_body);

    let header_matches = input
        .regex_info
        .header_parts
        .as_ref()
        .map(|parts| process_regex_parts(parts, &canonicalized_header))
        .map(|(verified, matches)| {
            assert!(verified);
            matches
        });
    let body_matches = input
        .regex_info
        .body_parts
        .as_ref()
        .map(|parts| process_regex_parts(parts, &cleaned_body))
        .map(|(verified, matches)| {
            assert!(verified);
            matches
        });

    let regex_matches = header_matches
        .into_iter()
        .chain(body_matches)
        .flatten()
        .collect();

    EmailWithRegexVerifierOutput {
        email: email_verifier_output,
        regex_matches,
    }
}
