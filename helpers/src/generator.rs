use anyhow::{anyhow, Result};
use cfdkim::{validate_header, verify_email_with_key, DkimPublicKey};
use mailparse::MailHeaderMap;
use slog::{o, Discard, Logger};
use zkemail_core::{Email, EmailWithRegex, PublicKey, RegexInfo};

use crate::{
    dkim::fetch_dkim_key, email::extract_email_body, regex::compile_regex_parts, RegexConfig,
};

pub async fn generate_email_inputs(from_domain: &str, raw_email: &[u8]) -> Result<Email> {
    let logger = Logger::root(Discard, o!());
    let email = mailparse::parse_mail(raw_email)?;

    let dkim_headers = email.headers.get_all_headers("DKIM-Signature");
    if dkim_headers.is_empty() {
        return Err(anyhow!("No DKIM signatures found"));
    }

    for header in dkim_headers.iter() {
        let dkim_header = match validate_header(&String::from_utf8_lossy(header.get_value_raw())) {
            Ok(h) if h.get_required_tag("d").to_lowercase() == from_domain.to_lowercase() => h,
            _ => {
                continue;
            }
        };

        let selector = dkim_header.get_required_tag("s");
        if let Ok((key, key_type)) = fetch_dkim_key(&logger, from_domain, &selector).await {
            if let Ok(public_key) = DkimPublicKey::try_from_bytes(&key, &key_type) {
                if let Ok(result) = verify_email_with_key(&logger, from_domain, &email, public_key)
                {
                    if result.with_detail().starts_with("pass") {
                        return Ok(Email {
                            from_domain: from_domain.to_string(),
                            raw_email: raw_email.to_vec(),
                            public_key: PublicKey { key, key_type },
                        });
                    }
                }
            }
        }
    }

    Err(anyhow!("No valid DKIM key found for any signature"))
}

pub async fn generate_email_with_regex_inputs(
    from_domain: &str,
    raw_email: &[u8],
    regex_config: &RegexConfig,
) -> Result<EmailWithRegex> {
    let email_inputs = generate_email_inputs(from_domain, raw_email).await?;
    let email = mailparse::parse_mail(&email_inputs.raw_email)?;

    let header_bytes = email.get_headers().get_raw_bytes();
    let email_body = extract_email_body(&email)?;

    let body_parts = compile_regex_parts(&regex_config.body_parts, &email_body)?;
    let header_parts = compile_regex_parts(&regex_config.header_parts, header_bytes)?;

    Ok(EmailWithRegex {
        email: email_inputs,
        regex_info: RegexInfo {
            header_parts,
            body_parts,
        },
    })
}
