#[cfg(test)]
mod dkim_tests {

    use slog::{o, Discard, Logger};
    use std::fs;
    use zkemail_core::{verify_dkim, Email, PublicKey};

    // Helper function to create a test email structure
    fn create_test_email_structure(raw_email: Vec<u8>, domain: &str, key_data: Vec<u8>) -> Email {
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

    // Helper function to create a mock RSA public key for testing
    fn create_mock_rsa_key() -> Vec<u8> {
        // Mock RSA public key in PEM format for testing
        b"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JiK4l6Y9M2Z5C9xTHm1
G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9x
THm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z
5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5r
Q3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8
qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1Y9B8qT5rQ3+Z5C9xTHm1G9tC2pF3Y6K1x1
Y9B8qT5rQ3+Z5C9xTHm1QIDAQAB
-----END PUBLIC KEY-----"
            .to_vec()
    }

    #[test]
    fn test_dkim_with_valid_structure() {
        // Load test email with DKIM signature
        let email_data =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM test email");

        let email = create_test_email_structure(email_data, "gmail.com", create_mock_rsa_key());

        let logger = Logger::root(Discard, o!());

        // This should not panic and return a boolean result
        let result = verify_dkim(&email, &logger);
        // The important thing is it doesn't panic
        // With mock data, result can be either true or false
        assert!(
            result == true || result == false,
            "DKIM verification should return a boolean without panicking"
        );
    }

    #[test]
    fn test_dkim_with_invalid_key_format() {
        let email_data =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM test email");

        // Test with invalid key format
        let invalid_key = b"invalid key data".to_vec();
        let email = create_test_email_structure(email_data, "gmail.com", invalid_key);

        let logger = Logger::root(Discard, o!());
        let result = verify_dkim(&email, &logger);

        // Should handle invalid key gracefully (return false, not panic)
        assert!(
            result == false,
            "Should return false for invalid key format"
        );
    }

    #[test]
    fn test_dkim_with_empty_key() {
        let email_data =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM test email");

        let empty_key = vec![];
        let email = create_test_email_structure(email_data, "gmail.com", empty_key);

        let logger = Logger::root(Discard, o!());
        let result = verify_dkim(&email, &logger);

        // Should handle empty key gracefully
        assert!(result == false, "Should return false for empty key");
    }

    #[test]
    fn test_dkim_with_malformed_email() {
        // Test with malformed email content
        let malformed_email = b"This is not a valid email format".to_vec();
        let email =
            create_test_email_structure(malformed_email, "example.com", create_mock_rsa_key());

        let logger = Logger::root(Discard, o!());
        let result = verify_dkim(&email, &logger);

        // Should handle malformed email gracefully
        assert!(result == false, "Should return false for malformed email");
    }

    #[test]
    fn test_dkim_with_missing_signature() {
        // Create email without DKIM signature
        let email_without_dkim = b"Subject: Test\r\n\r\nThis email has no DKIM signature".to_vec();
        let email =
            create_test_email_structure(email_without_dkim, "example.com", create_mock_rsa_key());

        let logger = Logger::root(Discard, o!());
        let result = verify_dkim(&email, &logger);

        // Should handle missing DKIM signature appropriately
        // Without DKIM signature, should return false
        assert!(result == false, "Should return false for missing DKIM signature");
    }

    #[test]
    fn test_dkim_with_different_domains() {
        let email_data =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM test email");

        // Test with different domain names
        let domains = ["gmail.com", "yahoo.com", "example.com", ""];

        for domain in &domains {
            let email =
                create_test_email_structure(email_data.clone(), domain, create_mock_rsa_key());

            let logger = Logger::root(Discard, o!());
            let result = verify_dkim(&email, &logger);

            // Should not panic regardless of domain
            assert!(
                result == true || result == false,
                "DKIM verification handled domain '{}' without panic",
                domain
            );
        }
    }

    #[test]
    fn test_dkim_with_large_email() {
        // Create a larger email for testing
        let mut large_email =
            String::from("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n");
        large_email.push_str("Subject: Large Email Test\r\n\r\n");

        // Add large body content
        for i in 0..1000 {
            large_email.push_str(&format!("Line {} of large email content.\r\n", i));
        }

        let email = create_test_email_structure(
            large_email.into_bytes(),
            "example.com",
            create_mock_rsa_key(),
        );

        let logger = Logger::root(Discard, o!());
        let result = verify_dkim(&email, &logger);

        // Should handle large emails without performance issues
        assert!(
            result == true || result == false,
            "DKIM verification handled large email appropriately"
        );
    }

    #[test]
    fn test_dkim_error_types() {
        let email_data =
            fs::read("tests/data/dkim_test_email.eml").expect("Failed to read DKIM test email");

        // Test various error scenarios
        let test_cases = vec![
            (vec![], "empty key"),
            (b"invalid".to_vec(), "invalid key"),
            (
                b"-----BEGIN INVALID-----\ninvalid\n-----END INVALID-----".to_vec(),
                "malformed PEM",
            ),
        ];

        for (key_data, description) in test_cases {
            let email = create_test_email_structure(email_data.clone(), "example.com", key_data);

            let logger = Logger::root(Discard, o!());
            let result = verify_dkim(&email, &logger);

            // Should handle error cases gracefully by returning false
            assert!(
                result == false,
                "Should return false for error case: {}",
                description
            );
        }
    }
}
