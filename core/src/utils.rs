use cfdkim::{verify_email_with_key, DkimPublicKey};
use mailparse::{parse_mail, ParsedMail};
use regex_automata::dfa::{dense, regex::Regex};
use sha2::{Digest, Sha256};
use slog::Logger;

use crate::{CompiledRegex, Email};

pub fn hash_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn extract_email_body(parsed_email: &ParsedMail) -> Vec<u8> {
    parsed_email
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map_or_else(
            || {
                parsed_email
                    .subparts
                    .get(0)
                    .map_or(parsed_email.get_body_raw().unwrap(), |part| {
                        part.get_body_raw().unwrap()
                    })
            },
            |part| part.get_body_raw().unwrap(),
        )
}

pub fn process_regex_parts(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    let capture_count = compiled_regexes
        .iter()
        .filter(|r| r.capture_str.is_some())
        .count();
    let mut regex_matches = Vec::with_capacity(capture_count);

    for part in compiled_regexes {
        let fwd = dense::DFA::from_bytes(&part.verify_re.fwd).unwrap().0;
        let rev = dense::DFA::from_bytes(&part.verify_re.bwd).unwrap().0;
        let re = Regex::builder().build_from_dfas(fwd, rev);

        let matches: Vec<_> = re.find_iter(input).collect();
        if matches.len() != 1 {
            return (false, regex_matches);
        }

        if let Some(capture_str) = &part.capture_str {
            let matched_str = std::str::from_utf8(&input[matches[0].range()]).unwrap();
            if !matched_str.contains(capture_str) || matched_str.matches(capture_str).count() != 1 {
                return (false, regex_matches);
            }
            regex_matches.push(capture_str.to_string());
        }
    }

    (true, regex_matches)
}

pub fn verify_dkim(input: &Email, logger: &Logger) -> bool {
    let parsed_email = parse_mail(&input.raw_email).unwrap();

    let public_key =
        DkimPublicKey::try_from_bytes(&input.public_key.key, &input.public_key.key_type).unwrap();

    let result =
        verify_email_with_key(logger, &input.from_domain, &parsed_email, public_key).unwrap();

    result.with_detail().starts_with("pass")
}
