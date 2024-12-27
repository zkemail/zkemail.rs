use anyhow::{anyhow, Result};
use cfdkim::{
    dns::from_tokio_resolver, public_key::retrieve_public_key, validate_header,
    verify_email_with_resolver,
};
use log::{debug, error, info, warn};
use mailparse::MailHeaderMap;
use regex_automata::{dfa::regex::Regex as DFARegex, meta::Regex as MetaRegex};
use slog::{o, Discard, Logger};
use std::{fs::File, io::Read, path::PathBuf};
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use zkemail_core::{CompiledRegex, Email, EmailWithRegex, PublicKey, RegexInfo, DFA};

use crate::structs::{RegexConfig, RegexPattern};

pub fn read_email_file(path: &PathBuf) -> Result<String> {
    use std::io::BufReader;
    let file = File::open(path).map_err(|e| anyhow!("Failed to open email file: {}", e))?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader
        .read_to_string(&mut contents)
        .map_err(|e| anyhow!("Failed to read email contents: {}", e))?;
    Ok(contents)
}

pub fn read_regex_config(path: &PathBuf) -> Result<RegexConfig> {
    let file = File::open(path).map_err(|e| anyhow!("Failed to open regex config file: {}", e))?;
    let config: RegexConfig =
        serde_json::from_reader(file).map_err(|e| anyhow!("Failed to read regex config: {}", e))?;
    Ok(config)
}

fn compile_regex_parts(parts: &[RegexPattern], input: &[u8]) -> Result<Vec<CompiledRegex>> {
    parts
        .iter()
        .map(|part| match part {
            RegexPattern::Match { pattern } => {
                let verify_dfa_re = DFARegex::new(pattern)?;
                if verify_dfa_re.find_iter(input).count() != 1 {
                    return Err(anyhow!("Input doesn't match regex pattern: {:?}", part));
                }

                Ok(CompiledRegex {
                    verify_re: DFA {
                        fwd: verify_dfa_re.forward().to_bytes_little_endian().0,
                        bwd: verify_dfa_re.reverse().to_bytes_little_endian().0,
                    },
                    capture_str: None,
                })
            }
            RegexPattern::Capture {
                prefix,
                capture,
                suffix,
            } => {
                let pattern_dfa = format!("{}{}{}", prefix, capture, suffix);
                let pattern_meta = format!("({})({})({})", prefix, capture, suffix);

                let verify_dfa_re = DFARegex::new(&pattern_dfa)?;
                if verify_dfa_re.find_iter(input).count() != 1 {
                    return Err(anyhow!("Input doesn't match regex pattern: {:?}", part));
                }

                let verify_meta_re = MetaRegex::new(&pattern_meta)?;
                let mut caps = verify_meta_re.create_captures();
                verify_meta_re.captures(input, &mut caps);

                let capture_str = caps
                    .get_group(2)
                    .and_then(|capture| std::str::from_utf8(&input[capture.range()]).ok())
                    .map(String::from)
                    .ok_or_else(|| anyhow!("No capture found"))?;

                Ok(CompiledRegex {
                    verify_re: DFA {
                        fwd: verify_dfa_re.forward().to_bytes_little_endian().0,
                        bwd: verify_dfa_re.reverse().to_bytes_little_endian().0,
                    },
                    capture_str: Some(capture_str),
                })
            }
        })
        .collect()
}

fn extract_email_body(email: &mailparse::ParsedMail) -> Result<Vec<u8>> {
    if email.subparts.is_empty() {
        return email.get_body_raw().map_err(Into::into);
    }

    email
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .or_else(|| email.subparts.first())
        .ok_or_else(|| anyhow!("No valid email body found"))?
        .get_body_raw()
        .map_err(Into::into)
}

pub async fn generate_email_inputs(from_domain: &str, email_path: &PathBuf) -> Result<Email> {
    let logger = Logger::root(Discard, o!());
    let raw_email = read_email_file(email_path)?;
    let email = mailparse::parse_mail(raw_email.as_bytes())
        .map_err(|e| anyhow!("Failed to parse email: {}", e))?;

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
                raw_email: raw_email.as_bytes().to_vec(),
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
