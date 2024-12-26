use mailparse::parse_mail;
use slog::{Discard, Logger, o};

use crate::{
    Email, EmailVerifierOutput, EmailWithRegex, EmailWithRegexVerifierOutput, extract_email_body,
    hash_bytes, process_regex_parts, verify_dkim,
};

pub fn verify_email(email: &Email) -> EmailVerifierOutput {
    let logger = Logger::root(Discard, o!());

    let verified = verify_dkim(email, &logger);

    EmailVerifierOutput {
        from_domain_hash: hash_bytes(email.from_domain.as_bytes()),
        public_key_hash: hash_bytes(&email.public_key.key),
        verified,
    }
}

pub fn verify_email_with_regex(input: &EmailWithRegex) -> EmailWithRegexVerifierOutput {
    let email_verifier_output = verify_email(&input.email);

    let parsed_email = parse_mail(&input.email.raw_email).unwrap();

    let header_bytes = parsed_email.get_headers().get_raw_bytes();
    let email_body = extract_email_body(&parsed_email);

    let (header_regex_verified, header_regex_matches) =
        process_regex_parts(&input.regex_info.header_parts, header_bytes);
    let (body_regex_verified, body_regex_matches) =
        process_regex_parts(&input.regex_info.body_parts, &email_body);

    EmailWithRegexVerifierOutput {
        email: email_verifier_output,
        header_regex_verified,
        body_regex_verified,
        header_regex_matches,
        body_regex_matches,
    }
}
