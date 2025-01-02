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

#[cfg(feature = "sp1")]
fn align_slice(bytes: &[u8]) -> Vec<u8> {
    let mut aligned = Vec::with_capacity(bytes.len() + 4);
    let offset = (aligned.as_ptr() as usize) % 4;
    let padding = vec![0; if offset == 0 { 0 } else { 4 - offset }];
    aligned.extend_from_slice(&padding);
    aligned.extend_from_slice(bytes);
    aligned
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
        #[cfg(feature = "sp1")]
        let fwd = align_slice(&part.verify_re.fwd);
        #[cfg(not(feature = "sp1"))]
        let fwd = &part.verify_re.fwd;

        #[cfg(feature = "sp1")]
        let bwd = align_slice(&part.verify_re.bwd);
        #[cfg(not(feature = "sp1"))]
        let bwd = &part.verify_re.bwd;

        let fwd = dense::DFA::from_bytes(&fwd).unwrap().0;
        let bwd = dense::DFA::from_bytes(&bwd).unwrap().0;
        let re = Regex::builder().build_from_dfas(fwd, bwd);

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
