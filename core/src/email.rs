use cfdkim::{verify_email_with_key, DkimPublicKey};
use mailparse::{parse_mail, ParsedMail};
use slog::Logger;

use crate::Email;

pub fn extract_email_body(parsed_email: &ParsedMail) -> Vec<u8> {
    parsed_email
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map_or_else(
            || {
                parsed_email
                    .subparts
                    .first()
                    .map_or(parsed_email.get_body_raw().unwrap(), |part| {
                        part.get_body_raw().unwrap()
                    })
            },
            |part| part.get_body_raw().unwrap(),
        )
}

pub fn verify_dkim(input: &Email, logger: &Logger) -> bool {
    let parsed_email = parse_mail(&input.raw_email).unwrap();

    let public_key =
        DkimPublicKey::try_from_bytes(&input.public_key.key, &input.public_key.key_type).unwrap();

    let result =
        verify_email_with_key(logger, &input.from_domain, &parsed_email, public_key).unwrap();

    result.with_detail().starts_with("pass")
}
