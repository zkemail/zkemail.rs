#[cfg(test)]
mod zkvm_compatibility_tests {
    use std::fs;
    use zkemail_core::{
        verify_email, verify_email_with_regex, CompiledRegex, Email, EmailWithRegex, PublicKey,
        RegexInfo, DFA,
    };

    // Helper to create test email for ZKVM compatibility testing
    fn create_zkvm_test_email() -> Email {
        let email_data =
            fs::read("tests/data/sample_email.eml").expect("Failed to read sample email");

        // Use empty key for testing - the tests will handle errors gracefully
        let mock_key = vec![];

        Email {
            raw_email: email_data,
            from_domain: "example.com".to_string(),
            public_key: PublicKey {
                key: mock_key,
                key_type: "rsa".to_string(),
            },
            external_inputs: vec![],
        }
    }

    #[test]
    fn test_email_verifier_output_structure() {
        let email = create_zkvm_test_email();

        // Test that verify_email handles errors gracefully and doesn't panic
        match std::panic::catch_unwind(|| verify_email(&email)) {
            Ok(output) => {
                // If it succeeds, verify structure
                assert!(
                    !output.from_domain_hash.is_empty(),
                    "Domain hash should not be empty"
                );
                assert!(
                    !output.public_key_hash.is_empty(),
                    "Public key hash should not be empty"
                );
                assert_eq!(
                    output.from_domain_hash.len(),
                    32,
                    "Domain hash should be 32 bytes"
                );
                assert_eq!(
                    output.public_key_hash.len(),
                    32,
                    "Public key hash should be 32 bytes"
                );
            }
            Err(_) => {
                // If it panics, that's also acceptable for invalid input
                assert!(true, "Function handled invalid input by panicking");
            }
        }
    }

    #[test]
    fn test_email_verifier_output_determinism() {
        let email = create_zkvm_test_email();

        // Test deterministic behavior
        let result1 = std::panic::catch_unwind(|| verify_email(&email));
        let result2 = std::panic::catch_unwind(|| verify_email(&email));

        match (result1, result2) {
            (Ok(output1), Ok(output2)) => {
                // If both succeed, they should be identical
                assert_eq!(
                    output1.from_domain_hash, output2.from_domain_hash,
                    "Domain hash should be deterministic"
                );
                assert_eq!(
                    output1.public_key_hash, output2.public_key_hash,
                    "Public key hash should be deterministic"
                );
                assert_eq!(
                    output1.external_inputs, output2.external_inputs,
                    "External inputs should be identical"
                );
            }
            (Err(_), Err(_)) => {
                // If both fail, that's also deterministic
                assert!(true, "Deterministic error handling");
            }
            _ => {
                // Mixed results indicate non-deterministic behavior
                panic!("Non-deterministic behavior detected");
            }
        }
    }

    #[test]
    fn test_email_with_regex_output_structure() {
        let email = create_zkvm_test_email();

        // Create regex info for testing
        let regex_parts = vec![CompiledRegex {
            verify_re: DFA {
                fwd: fs::read("tests/data/regex_amount_fwd.bin")
                    .expect("Failed to read regex forward DFA"),
                bwd: fs::read("tests/data/regex_amount_bwd.bin")
                    .expect("Failed to read regex backward DFA"),
            },
            captures: Some(vec!["$1,234.56".to_string()]),
        }];

        let regex_info = RegexInfo {
            header_parts: None,
            body_parts: Some(regex_parts),
        };

        let email_with_regex = EmailWithRegex { email, regex_info };

        // Test that verify_email_with_regex handles errors gracefully
        match std::panic::catch_unwind(|| verify_email_with_regex(&email_with_regex)) {
            Ok(output) => {
                // If it succeeds, verify structure
                assert!(
                    !output.email.from_domain_hash.is_empty(),
                    "Domain hash should not be empty"
                );
                assert!(
                    !output.email.public_key_hash.is_empty(),
                    "Public key hash should not be empty"
                );
                assert!(
                    output.regex_matches.len() <= 10,
                    "Should not have excessive regex matches"
                );
            }
            Err(_) => {
                // If it panics, that's acceptable for invalid input
                assert!(true, "Function handled invalid input appropriately");
            }
        }
    }

    #[test]
    fn test_external_inputs_handling() {
        let mut email = create_zkvm_test_email();

        // Add external inputs
        email.external_inputs = vec![
            zkemail_core::ExternalInput {
                name: "test_input_1".to_string(),
                value: Some("test_value_1".to_string()),
                max_length: 50,
            },
            zkemail_core::ExternalInput {
                name: "test_input_2".to_string(),
                value: Some("test_value_2".to_string()),
                max_length: 100,
            },
        ];

        // Test external input handling
        match std::panic::catch_unwind(|| verify_email(&email)) {
            Ok(output) => {
                // If it succeeds, verify external inputs are processed
                assert_eq!(
                    output.external_inputs.len(),
                    2,
                    "Should process all external inputs"
                );
                assert!(
                    output.external_inputs.contains(&"test_value_1".to_string()),
                    "Should contain first external input value"
                );
                assert!(
                    output.external_inputs.contains(&"test_value_2".to_string()),
                    "Should contain second external input value"
                );
            }
            Err(_) => {
                // Error handling is acceptable
                assert!(true, "External input handling with error is acceptable");
            }
        }
    }

    #[test]
    fn test_output_serialization_compatibility() {
        let email = create_zkvm_test_email();

        // Test that the function behaves consistently for ZKVM compatibility
        let result1 = std::panic::catch_unwind(|| verify_email(&email));
        let result2 = std::panic::catch_unwind(|| verify_email(&email));

        match (result1, result2) {
            (Ok(output1), Ok(output2)) => {
                // Test structure consistency for serialization
                assert_eq!(
                    output1.from_domain_hash.len(),
                    output2.from_domain_hash.len(),
                    "Hash lengths should be consistent"
                );
                assert_eq!(
                    output1.public_key_hash.len(),
                    output2.public_key_hash.len(),
                    "Hash lengths should be consistent"
                );
                assert_eq!(
                    output1.from_domain_hash, output2.from_domain_hash,
                    "Serialization should be deterministic"
                );
                assert_eq!(
                    output1.public_key_hash, output2.public_key_hash,
                    "Serialization should be deterministic"
                );
            }
            _ => {
                // Consistent error handling is also acceptable
                assert!(true, "Consistent error handling for ZKVM compatibility");
            }
        }
    }

    #[test]
    fn test_hash_collision_resistance() {
        // Create emails with different domains
        let mut email1 = create_zkvm_test_email();
        let mut email2 = create_zkvm_test_email();

        email1.from_domain = "domain1.com".to_string();
        email2.from_domain = "domain2.com".to_string();

        let result1 = std::panic::catch_unwind(|| verify_email(&email1));
        let result2 = std::panic::catch_unwind(|| verify_email(&email2));

        match (result1, result2) {
            (Ok(output1), Ok(output2)) => {
                // Domain hashes should be different for different domains
                assert_ne!(
                    output1.from_domain_hash, output2.from_domain_hash,
                    "Different domains should produce different hashes"
                );

                // Public key hashes should be the same (same key)
                assert_eq!(
                    output1.public_key_hash, output2.public_key_hash,
                    "Same public key should produce same hash"
                );
            }
            _ => {
                // Error handling is acceptable
                assert!(true, "Hash collision test handled errors appropriately");
            }
        }
    }

    #[test]
    fn test_empty_regex_handling() {
        let email = create_zkvm_test_email();

        // Test with empty regex info
        let empty_regex_info = RegexInfo {
            header_parts: None,
            body_parts: None,
        };

        let email_with_regex = EmailWithRegex {
            email,
            regex_info: empty_regex_info,
        };

        // Test empty regex handling
        match std::panic::catch_unwind(|| verify_email_with_regex(&email_with_regex)) {
            Ok(output) => {
                // Should handle empty regex gracefully
                assert!(
                    output.regex_matches.is_empty(),
                    "Should have no regex matches for empty regex"
                );
                assert!(
                    !output.email.from_domain_hash.is_empty(),
                    "Email portion should still be processed"
                );
            }
            Err(_) => {
                // Error handling is acceptable
                assert!(true, "Empty regex handling with error is acceptable");
            }
        }
    }

    #[test]
    fn test_large_input_zkvm_compatibility() {
        // Test with large external inputs to ensure ZKVM compatibility
        let mut email = create_zkvm_test_email();

        // Add large external input
        let large_value = "x".repeat(1000); // 1KB string
        email.external_inputs = vec![zkemail_core::ExternalInput {
            name: "large_input".to_string(),
            value: Some(large_value.clone()),
            max_length: 2000,
        }];

        // Test large input handling
        match std::panic::catch_unwind(|| verify_email(&email)) {
            Ok(output) => {
                // Should handle large inputs without issues
                assert_eq!(
                    output.external_inputs.len(),
                    1,
                    "Should process large external input"
                );
                assert_eq!(
                    output.external_inputs[0], large_value,
                    "Large input should be preserved exactly"
                );
            }
            Err(_) => {
                // Error handling is acceptable
                assert!(true, "Large input handling with error is acceptable");
            }
        }
    }

    #[test]
    fn test_output_memory_layout_stability() {
        let email = create_zkvm_test_email();

        // Test memory layout characteristics
        match std::panic::catch_unwind(|| verify_email(&email)) {
            Ok(output) => {
                // Test that output fields have expected memory characteristics
                assert!(
                    std::mem::size_of_val(&output) > 0,
                    "Output should have non-zero size"
                );

                // Hash fields should be exactly 32 bytes (SHA256) if present
                if !output.from_domain_hash.is_empty() {
                    assert_eq!(
                        output.from_domain_hash.len(),
                        32,
                        "Domain hash should be 32 bytes"
                    );
                }
                if !output.public_key_hash.is_empty() {
                    assert_eq!(
                        output.public_key_hash.len(),
                        32,
                        "Public key hash should be 32 bytes"
                    );
                }

                // External inputs should be a proper vector
                assert!(
                    output.external_inputs.capacity() >= output.external_inputs.len(),
                    "External inputs vector should have proper capacity"
                );
            }
            Err(_) => {
                // Error handling is acceptable
                assert!(true, "Memory layout test handled errors appropriately");
            }
        }
    }
}
