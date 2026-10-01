use anyhow::{anyhow, Result};
use cfdkim::{validate_header, DkimPublicKey};
use mailparse::MailHeaderMap;
use slog::{o, Discard, Logger};
use zkemail_core::{
    canonicalize_verified_email, remove_quoted_printable_soft_breaks, verify_dkim, Email,
    EmailWithRegex, ExternalInput, PublicKey, RegexInfo,
};

use crate::{dkim::fetch_dkim_key_candidates, regex::compile_regex_parts, RegexConfig};

pub async fn generate_email_inputs(
    from_domain: &str,
    raw_email: &[u8],
    external_inputs: Option<Vec<ExternalInput>>,
) -> Result<Email> {
    let logger = Logger::root(Discard, o!());
    let email = mailparse::parse_mail(raw_email)?;

    let dkim_headers = email.headers.get_all_headers("DKIM-Signature");
    if dkim_headers.is_empty() {
        return Err(anyhow!("No DKIM signatures found"));
    }

    let mut errors = Vec::new();
    let mut tried_selectors = Vec::new();
    for header in dkim_headers.iter() {
        let dkim_header = match validate_header(&String::from_utf8_lossy(header.get_value_raw())) {
            Ok(h) if h.get_required_tag("d").eq_ignore_ascii_case(from_domain) => h,
            _ => continue,
        };

        let selector = dkim_header.get_required_tag("s");
        if tried_selectors.contains(&selector) {
            continue;
        }
        tried_selectors.push(selector.clone());

        // REASON: every candidate key (current DNS key and every archived key for the
        // selector) is tried, since the signing key may have been rotated out of DNS. The
        // check is the same one the zkVM program runs (core::verify_dkim), so the key returned
        // here is one the program accepts.
        let candidates = match fetch_dkim_key_candidates(&logger, from_domain, &selector).await {
            Ok(c) => c,
            Err(e) => {
                errors.push(format!("s={selector}: {e}"));
                continue;
            }
        };
        for candidate in candidates {
            let input = Email {
                from_domain: from_domain.to_string(),
                raw_email: raw_email.to_vec(),
                public_key: PublicKey {
                    key: candidate.key,
                    key_type: candidate.key_type,
                },
                external_inputs: external_inputs.clone().unwrap_or_default(),
            };
            if DkimPublicKey::try_from_bytes(&input.public_key.key, &input.public_key.key_type)
                .is_ok()
                && verify_dkim(&input, &logger)
            {
                return Ok(input);
            }
        }
        errors.push(format!("s={selector}: no candidate key verifies"));
    }

    Err(anyhow!(
        "No valid DKIM key found for any signature from {from_domain} ({})",
        errors.join("; ")
    ))
}

pub async fn generate_email_with_regex_inputs(
    from_domain: &str,
    raw_email: &[u8],
    regex_config: &RegexConfig,
    external_inputs: Option<Vec<ExternalInput>>,
) -> Result<EmailWithRegex> {
    let email_inputs = generate_email_inputs(from_domain, raw_email, external_inputs).await?;

    // NOTE: must match core::verify_email_with_regex, which runs the regexes over the
    // verified signature's canonicalization (not the first DKIM-Signature's).
    let (canonicalized_header, canonicalized_body) =
        canonicalize_verified_email(&email_inputs, &Logger::root(Discard, o!()));

    let (cleaned_body, _) = remove_quoted_printable_soft_breaks(canonicalized_body);

    let body_parts = regex_config
        .body_parts
        .as_ref()
        .filter(|parts| !parts.is_empty())
        .map(|parts| compile_regex_parts(parts, &cleaned_body))
        .transpose()?;
    let header_parts = regex_config
        .header_parts
        .as_ref()
        .filter(|parts| !parts.is_empty())
        .map(|parts| compile_regex_parts(parts, &canonicalized_header))
        .transpose()?;

    Ok(EmailWithRegex {
        email: email_inputs,
        regex_info: RegexInfo {
            header_parts,
            body_parts,
        },
    })
}
