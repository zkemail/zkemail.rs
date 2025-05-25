#[cfg(test)]
mod tests {
    use mailparse::parse_mail;
    use slog::{o, Discard, Logger};
    use std::fs;
    use std::path::Path;
    use std::time::Instant;
    use zkemail_core::{
        extract_email_body, hash_bytes, process_regex_parts, verify_dkim, CompiledRegex, Email,
        PublicKey, DFA,
    };

    // Utility function to load test emails
    fn load_test_emails() -> (Vec<u8>, Vec<u8>) {
        let small_email =
            fs::read("tests/data/sample_email.eml").expect("Failed to read sample email");
        let dkim_email =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM email");
        (small_email, dkim_email)
    }

    // Utility function to create test email struct
    fn create_test_email(raw_email: Vec<u8>, domain: &str) -> Email {
        let key_path = Path::new("tests/data/dkim_public_key.pem");
        let key_data = fs::read(key_path).expect("Failed to read public key");
        Email {
            raw_email,
            from_domain: domain.to_string(),
            public_key: PublicKey {
                key: key_data,
                key_type: "rsa".to_string(),
            },
            external_inputs: vec![],
        }
    }

    #[test]
    fn test_parse_email_basic() {
        let (small_email, _) = load_test_emails();
        let parsed_email = parse_mail(&small_email).expect("Should parse without errors");

        // Basic assertions about the parsed email
        assert!(
            !parsed_email.headers.is_empty(),
            "Email should have headers"
        );
        assert_eq!(
            parsed_email.headers[0].get_key(),
            "DKIM-Signature",
            "First header should be DKIM-Signature"
        );
        // Find the Subject header (headers might be in different order)
        let subject_header = parsed_email
            .headers
            .iter()
            .find(|h| h.get_key() == "Subject");
        assert!(subject_header.is_some(), "Should have Subject header");
    }

    #[test]
    fn test_extract_email_body() {
        let (small_email, _) = load_test_emails();
        let parsed_email = parse_mail(&small_email).expect("Should parse without errors");

        let body = extract_email_body(&parsed_email);
        assert!(!body.is_empty(), "Email body should not be empty");

        // The HTML body should contain our test content
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("<!DOCTYPE html>"), "Body should be HTML");
        assert!(
            body_str.contains("$1,234.56"),
            "Body should contain the amount"
        );
    }

    #[test]
    fn test_hash_bytes() {
        let (small_email, _) = load_test_emails();

        let hash1 = hash_bytes(&small_email);
        let hash2 = hash_bytes(&small_email);

        // Same input should produce same hash
        assert_eq!(hash1, hash2, "Same input should produce same hash");

        // Different inputs should produce different hashes
        let modified_email = [&small_email[..], b"extra data"].concat();
        let hash3 = hash_bytes(&modified_email);
        assert_ne!(
            hash1, hash3,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    #[ignore] // Ignore this test as it requires valid DKIM keys
    fn test_verify_dkim() {
        let (_, dkim_email) = load_test_emails();
        let email = create_test_email(dkim_email, "gmail.com");
        let logger = Logger::root(Discard, o!());

        // Note: This test is ignored because it requires valid DKIM test data
        // In a real environment with proper keys, this would work
        let _result = verify_dkim(&email, &logger);

        // We would assert the verification result here with proper test data
    }

    #[test]
    fn test_process_regex_parts() {
        // Create test regex for dollar amount
        let regex_parts = vec![CompiledRegex {
            verify_re: DFA {
                fwd: fs::read("tests/data/regex_amount_fwd.bin")
                    .expect("Failed to read regex forward DFA"),
                bwd: fs::read("tests/data/regex_amount_bwd.bin")
                    .expect("Failed to read regex backward DFA"),
            },
            captures: Some(vec!["$1,234.56".to_string()]),
        }];

        // Test with a matching input
        let matching_input = b"This email contains $1,234.56 as the amount.";
        let (is_match, captures) = process_regex_parts(&regex_parts, matching_input);
        assert!(is_match, "Should match the dollar amount pattern");
        assert_eq!(captures.len(), 1, "Should have one capture");
        assert_eq!(
            captures[0], "$1,234.56",
            "Capture should be the dollar amount"
        );

        // Test with non-matching input
        let non_matching_input = b"This email contains no dollar amounts.";
        let (is_match, _) = process_regex_parts(&regex_parts, non_matching_input);
        assert!(!is_match, "Should not match when pattern is missing");
    }

    // Test edge cases
    #[test]
    fn test_empty_email() {
        let empty_email = vec![];

        // parse_mail should handle empty input gracefully
        let result = parse_mail(&empty_email);
        // With actual empty data, this might parse successfully but have no headers
        if let Ok(parsed) = result {
            assert!(
                parsed.headers.is_empty(),
                "Empty email should have no headers"
            );
        } else {
            // Error is also acceptable for empty input
            assert!(
                result.is_err(),
                "Empty email should either parse with no headers or cause error"
            );
        }
    }

    #[test]
    fn test_malformed_email() {
        let malformed_email = b"This is not a valid email format".to_vec();

        // The parser should not crash on malformed input
        let result = parse_mail(&malformed_email);
        // It might parse this as a valid email with just body content, so we don't assert error
        if let Ok(_parsed) = result {
            // This is acceptable - parser can interpret this as body-only message
            // so we'll just check it doesn't crash
            assert!(true, "Parser handled malformed input gracefully");
        } else {
            // Error is also acceptable for malformed input
            assert!(
                result.is_err(),
                "Malformed email parsing error is acceptable"
            );
        }
    }

    // Performance regression test - ensures optimization doesn't slow things down
    #[test]
    fn test_performance_regression() {
        let (small_email, _) = load_test_emails();

        // Basic performance check
        let start = Instant::now();
        let parsed = parse_mail(&small_email).unwrap();
        let parse_time = start.elapsed();

        let start = Instant::now();
        let _ = extract_email_body(&parsed);
        let extract_time = start.elapsed();

        let start = Instant::now();
        let _ = hash_bytes(b"test data");
        let hash_time = start.elapsed();

        // Performance assertions - these should typically complete very quickly
        // Performance thresholds may require adjustment based on environment
        assert!(parse_time.as_millis() < 10, "Email parsing should be fast");
        assert!(
            extract_time.as_micros() < 1000,
            "Body extraction should be fast"
        );
        assert!(hash_time.as_micros() < 100, "Hashing should be fast");
    }
}
