//! Regression tests: the zkVM program (zkemail-core) must run its regexes over the header of
//! the DKIM-Signature it verified, and must accept a key that signed any same-domain signature.
use cfdkim::{canonicalization, canonicalize_signed_email, DkimPrivateKey, SignerBuilder};
use chrono::TimeZone;
use regex_automata::dfa::regex::Regex as DFARegex;
use rsa::{pkcs1::EncodeRsaPublicKey, RsaPrivateKey};
use zkemail_core::{
    verify_dkim, verify_email_with_regex, CompiledRegex, Email, EmailWithRegex, PublicKey,
    RegexInfo,
};

use crate::regex::create_dfa;

const DOMAIN: &str = "example.com";

fn logger() -> slog::Logger {
    slog::Logger::root(slog::Discard, slog::o!())
}

fn sign(raw_email: &str, key: &RsaPrivateKey, selector: &str) -> String {
    let email = mailparse::parse_mail(raw_email.as_bytes()).unwrap();
    let logger = logger();
    let header = SignerBuilder::new()
        .with_signed_headers(&["From", "Subject"])
        .unwrap()
        .with_private_key(DkimPrivateKey::Rsa(key.clone()))
        .with_header_canonicalization(canonicalization::Type::Relaxed)
        .with_body_canonicalization(canonicalization::Type::Relaxed)
        .with_selector(selector)
        .with_signing_domain(DOMAIN)
        .with_logger(&logger)
        .with_time(chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .build()
        .unwrap()
        .sign(&email)
        .unwrap();
    format!("{}\r\n{}", header, raw_email)
}

fn email_input(raw: &str, key: &RsaPrivateKey) -> Email {
    Email {
        from_domain: DOMAIN.to_string(),
        raw_email: raw.as_bytes().to_vec(),
        public_key: PublicKey {
            key: key.to_public_key().to_pkcs1_der().unwrap().as_bytes().to_vec(),
            key_type: "rsa".to_string(),
        },
        external_inputs: vec![],
    }
}

fn header_regex(pattern: &str) -> CompiledRegex {
    CompiledRegex {
        verify_re: create_dfa(&DFARegex::new(pattern).unwrap()),
        captures: Some(vec![pattern.to_string()]),
        max_length: None,
    }
}

const BASE: &str = "From: Alice <alice@example.com>\r\nSubject: real subject\r\n\r\nHello\r\n";

/// A message carrying two DKIM-Signatures where the first one does not verify and lists
/// different headers than the verified example.com signature.
fn tampered(key: &RsaPrivateKey) -> String {
    format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=other.example; s=x;\r\n h=from:subject:subject; bh=AAAA; b=AAAA\r\nSubject: unsigned subject\r\n{}",
        sign(BASE, key, "s1")
    )
}

#[test]
fn regexes_run_over_the_verified_signature_header() {
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
    let raw = tampered(&key);
    let email = email_input(&raw, &key);
    assert!(verify_dkim(&email, &logger()));

    // The first-signature canonicalization differs from the verified one...
    let (first_header, _, _) = canonicalize_signed_email(raw.as_bytes()).unwrap();
    assert!(String::from_utf8_lossy(&first_header).contains("unsigned subject"));

    // ...and the program must only match against the verified signature's header.
    let forged = EmailWithRegex {
        email: email_input(&raw, &key),
        regex_info: RegexInfo {
            header_parts: Some(vec![header_regex("unsigned subject")]),
            body_parts: None,
        },
    };
    assert!(std::panic::catch_unwind(|| verify_email_with_regex(&forged)).is_err());

    // A header the verified signature does cover still matches.
    let honest = EmailWithRegex {
        email: email_input(&raw, &key),
        regex_info: RegexInfo {
            header_parts: Some(vec![header_regex("real subject")]),
            body_parts: None,
        },
    };
    assert_eq!(
        verify_email_with_regex(&honest).regex_matches,
        vec!["real subject".to_string()]
    );
}

#[test]
fn key_of_second_same_domain_signature_verifies() {
    let mut rng = rand::thread_rng();
    let first = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let second = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    // `second` signs first, so its DKIM-Signature ends up below the one made with `first`.
    let raw = sign(&sign(BASE, &second, "s2"), &first, "s1");

    assert!(verify_dkim(&email_input(&raw, &first), &logger()));
    assert!(verify_dkim(&email_input(&raw, &second), &logger()));
    let stranger = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    assert!(!verify_dkim(&email_input(&raw, &stranger), &logger()));
}
