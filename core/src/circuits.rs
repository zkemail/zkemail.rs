use mailparse::parse_mail;
use slog::{o, Discard, Logger};

use crate::{
    extract_email_body, hash_bytes, process_regex_parts, verify_dkim, Email, EmailVerifierOutput,
    EmailWithRegex, EmailWithRegexVerifierOutput,
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
    let email_verifier_output = verify_email(&input.email);

    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let header_bytes = parsed_email.get_headers().get_raw_bytes();
    let email_body = extract_email_body(&parsed_email);

    let header_matches = input
        .regex_info
        .header_parts
        .as_ref()
        .map(|parts| process_regex_parts(parts, header_bytes))
        .map(|(verified, matches)| {
            assert!(verified);
            matches
        });

    let body_matches = input
        .regex_info
        .body_parts
        .as_ref()
        .map(|parts| process_regex_parts(parts, &email_body))
        .map(|(verified, matches)| {
            assert!(verified);
            matches
        });

    let pdf_matches = input
        .regex_info
        .pdf_parts
        .as_ref()
        .map(|parts| process_regex_parts(parts, &email_body))
        .map(|(verified, matches)| {
            assert!(verified);
            matches
        });

    let regex_matches = header_matches
        .into_iter()
        .chain(body_matches.into_iter())
        .chain(pdf_matches.into_iter())
        .flatten()
        .collect();

    EmailWithRegexVerifierOutput {
        email: email_verifier_output,
        regex_matches,
    }
}
