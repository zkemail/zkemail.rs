use anyhow::{anyhow, Result};
use cfdkim::{
    dns::from_tokio_resolver, public_key::retrieve_public_key, validate_header,
    verify_email_with_resolver,
};
use log::{debug, error, info, warn};
use mailparse::MailHeaderMap;
use slog::{o, Discard, Logger};
use std::path::PathBuf;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use zkemail_core::{Email, EmailWithRegex, PublicKey, RegexInfo};

use crate::{
    email::extract_email_body,
    file::{read_email_file, read_regex_config},
    regex::compile_regex_parts,
};

pub async fn generate_email_inputs(from_domain: &str, email_path: &PathBuf) -> Result<Email> {
    let logger = Logger::root(Discard, o!());
    let raw_email = read_email_file(email_path)?;
    let email =
        mailparse::parse_mail(&raw_email).map_err(|e| anyhow!("Failed to parse email: {}", e))?;

    debug!("Looking for DKIM signatures...");
    let dkim_headers = email.headers.get_all_headers("DKIM-Signature");
    if dkim_headers.is_empty() {
        warn!("No DKIM signatures found in email!");
        return Err(anyhow!("No DKIM signatures found"));
    }

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["8.8.8.8".parse().unwrap()], 53, true),
        ),
        ResolverOpts::default(),
    );
    let resolver = from_tokio_resolver(resolver);

    let mut extracted_public_key = None;
    let mut key_type = None;

    for header in dkim_headers.iter() {
        let header_value = String::from_utf8_lossy(header.get_value_raw());

        let dkim_header = match validate_header(&header_value) {
            Ok(h) => h,
            Err(e) => {
                debug!("Invalid DKIM header: {}", e);
                continue;
            }
        };

        if dkim_header.get_required_tag("d").to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let algo = dkim_header.get_required_tag("a");
        let current_key_type = if algo.starts_with("rsa-") {
            "rsa"
        } else if algo.starts_with("ed25519-") {
            "ed25519"
        } else {
            debug!("Unsupported algorithm: {}", algo);
            continue;
        };

        let selector = dkim_header.get_required_tag("s");
        match retrieve_public_key(&logger, resolver.clone(), from_domain.to_string(), selector)
            .await
        {
            Ok(pk) => {
                extracted_public_key = Some(pk.to_vec());
                key_type = Some(current_key_type.to_string());
                break;
            }
            Err(e) => {
                debug!("Failed to retrieve public key: {}", e);
                continue;
            }
        }
    }

    let result = verify_email_with_resolver(&logger, from_domain, &email, resolver)
        .await
        .map_err(|e| anyhow!("Failed to verify email: {}", e))?;

    match result {
        result if result.with_detail().starts_with("pass") => {
            info!("DKIM verification passed: {}", result.with_detail());

            let email_inputs = Email {
                from_domain: from_domain.to_string(),
                raw_email,
                public_key: PublicKey {
                    key: extracted_public_key.ok_or_else(|| anyhow!("No public key extracted"))?,
                    key_type: key_type.ok_or_else(|| anyhow!("No key type found"))?,
                },
            };

            Ok(email_inputs)
        }
        result => {
            error!("DKIM verification failed: {}", result.with_detail());
            Err(anyhow!(
                "DKIM verification failed: {}",
                result.with_detail()
            ))
        }
    }
}

pub async fn generate_email_with_regex_inputs(
    from_domain: &str,
    email_path: &PathBuf,
    config_path: &PathBuf,
) -> Result<EmailWithRegex> {
    let email_inputs = generate_email_inputs(from_domain, email_path).await?;
    let email = mailparse::parse_mail(&email_inputs.raw_email)?;

    let header_bytes = email.get_headers().get_raw_bytes();
    let email_body = extract_email_body(&email)?;

    let regex_config = read_regex_config(config_path)?;
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
