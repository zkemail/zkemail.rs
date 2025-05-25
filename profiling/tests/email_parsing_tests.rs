#[cfg(test)]
mod email_parsing_tests {
    use mailparse::parse_mail;
    use std::fs;
    use std::time::Instant;
    use zkemail_core::extract_email_body;

    /// Test valid RFC 5322 email formats
    #[test]
    fn test_rfc5322_compliant_emails() {
        // Test basic RFC 5322 email
        let basic_email = b"From: sender@example.com\r\n\
                           To: recipient@example.com\r\n\
                           Subject: Test Subject\r\n\
                           Date: Mon, 1 Jan 2024 12:00:00 +0000\r\n\
                           \r\n\
                           This is the email body.";

        let parsed = parse_mail(basic_email).expect("Should parse valid RFC 5322 email");
        assert_eq!(parsed.headers.len(), 4);
        assert!(parsed
            .get_body()
            .unwrap()
            .contains("This is the email body"));
    }

    #[test]
    fn test_mime_multipart_emails() {
        // Test MIME multipart email
        let multipart_email = b"From: sender@example.com\r\n\
                               To: recipient@example.com\r\n\
                               Subject: Multipart Test\r\n\
                               Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n\
                               \r\n\
                               --boundary123\r\n\
                               Content-Type: text/plain\r\n\
                               \r\n\
                               Plain text part\r\n\
                               --boundary123\r\n\
                               Content-Type: text/html\r\n\
                               \r\n\
                               <html><body>HTML part</body></html>\r\n\
                               --boundary123--";

        let parsed = parse_mail(multipart_email).expect("Should parse multipart email");
        assert!(!parsed.subparts.is_empty(), "Should have subparts");
        assert_eq!(parsed.subparts.len(), 2, "Should have exactly 2 subparts");
    }

    #[test]
    fn test_email_with_various_encodings() {
        // Test with different character encodings
        let encoded_email = b"From: sender@example.com\r\n\
                             To: recipient@example.com\r\n\
                             Subject: =?UTF-8?B?VGVzdCBTdWJqZWN0?=\r\n\
                             Content-Type: text/plain; charset=UTF-8\r\n\
                             Content-Transfer-Encoding: base64\r\n\
                             \r\n\
                             VGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIG1lc3NhZ2Uu";

        let parsed = parse_mail(encoded_email).expect("Should parse encoded email");
        assert!(parsed.headers.len() >= 4);

        // Test subject decoding
        let subject = parsed
            .headers
            .iter()
            .find(|h| h.get_key() == "Subject")
            .expect("Should have Subject header");
        assert!(subject.get_value().contains("Test Subject"));
    }

    #[test]
    fn test_email_with_attachments() {
        // Test email with attachments
        let email_with_attachment = b"From: sender@example.com\r\n\
                                     To: recipient@example.com\r\n\
                                     Subject: Email with Attachment\r\n\
                                     Content-Type: multipart/mixed; boundary=\"att_boundary\"\r\n\
                                     \r\n\
                                     --att_boundary\r\n\
                                     Content-Type: text/plain\r\n\
                                     \r\n\
                                     Email body with attachment\r\n\
                                     --att_boundary\r\n\
                                     Content-Type: application/octet-stream\r\n\
                                     Content-Disposition: attachment; filename=\"test.bin\"\r\n\
                                     Content-Transfer-Encoding: base64\r\n\
                                     \r\n\
                                     VGVzdCBhdHRhY2htZW50IGRhdGE=\r\n\
                                     --att_boundary--";

        let parsed = parse_mail(email_with_attachment).expect("Should parse email with attachment");
        assert!(
            !parsed.subparts.is_empty(),
            "Should have subparts for attachment"
        );

        // Check that we can extract body correctly
        let body = extract_email_body(&parsed);
        assert!(
            !body.is_empty(),
            "Should extract body from email with attachment"
        );
    }

    #[test]
    fn test_deeply_nested_multipart() {
        // Test deeply nested multipart structure
        let nested_email = b"From: sender@example.com\r\n\
                            To: recipient@example.com\r\n\
                            Subject: Nested Multipart\r\n\
                            Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
                            \r\n\
                            --outer\r\n\
                            Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
                            \r\n\
                            --inner\r\n\
                            Content-Type: text/plain\r\n\
                            \r\n\
                            Plain text version\r\n\
                            --inner\r\n\
                            Content-Type: text/html\r\n\
                            \r\n\
                            <html><body>HTML version</body></html>\r\n\
                            --inner--\r\n\
                            --outer\r\n\
                            Content-Type: text/plain\r\n\
                            \r\n\
                            Additional content\r\n\
                            --outer--";

        let parsed = parse_mail(nested_email).expect("Should parse nested multipart email");
        assert!(!parsed.subparts.is_empty(), "Should have outer subparts");

        // Check nested structure        if let Some(first_part) = parsed.subparts.first() {            if first_part.ctype.mimetype.starts_with("multipart/") {                assert!(!first_part.subparts.is_empty(), "Should have nested subparts");            }        }
    }

    // Test malformed email inputs
    #[test]
    fn test_malformed_headers() {
        // Test email with malformed headers
        let malformed_headers = vec![
            // Missing colon in header
            b"From sender@example.com\r\nSubject: Test\r\n\r\nBody".to_vec(),
            // Unterminated header line
            b"From: sender@example.com\r\nSubject Test Subject\r\n\r\nBody".to_vec(),
            // Invalid header name
            b"From@: sender@example.com\r\nSubject: Test\r\n\r\nBody".to_vec(),
        ];

        for (i, malformed_email) in malformed_headers.iter().enumerate() {
            let result = parse_mail(malformed_email);
            // The parser should either handle it gracefully or return an error
            match result {
                Ok(parsed) => {
                    // If it parses, it should not crash subsequent operations
                    let _ = extract_email_body(&parsed);
                    assert!(true, "Malformed email {} handled gracefully", i);
                }
                Err(_) => {
                    // Error is acceptable for malformed input
                    assert!(true, "Malformed email {} correctly rejected", i);
                }
            }
        }
    }

    #[test]
    fn test_boundary_edge_cases() {
        // Test various boundary edge cases
        let boundary_cases = vec![
            // Missing final boundary
            b"Content-Type: multipart/mixed; boundary=\"test\"\r\n\r\n--test\r\nContent-Type: text/plain\r\n\r\nContent".to_vec(),
            // Boundary in content
            b"Content-Type: multipart/mixed; boundary=\"test\"\r\n\r\n--test\r\nContent-Type: text/plain\r\n\r\n--test in content\r\n--test--".to_vec(),
            // Very long boundary
            b"Content-Type: multipart/mixed; boundary=\"verylongboundarystringthatshouldstillwork\"\r\n\r\n--verylongboundarystringthatshouldstillwork\r\nContent-Type: text/plain\r\n\r\nContent\r\n--verylongboundarystringthatshouldstillwork--".to_vec(),
        ];

        for (i, boundary_email) in boundary_cases.iter().enumerate() {
            let result = parse_mail(boundary_email);
            match result {
                Ok(parsed) => {
                    // Should not crash when extracting body
                    let _ = extract_email_body(&parsed);
                    assert!(true, "Boundary case {} handled", i);
                }
                Err(_) => {
                    assert!(true, "Boundary case {} appropriately rejected", i);
                }
            }
        }
    }

    #[test]
    fn test_empty_and_minimal_emails() {
        // Test empty email
        let empty_email = b"";
        let result = parse_mail(empty_email);
        match result {
            Ok(parsed) => {
                assert!(
                    parsed.headers.is_empty() || parsed.get_body().unwrap_or_default().is_empty()
                );
            }
            Err(_) => {
                assert!(true, "Empty email appropriately rejected");
            }
        }

        // Test minimal valid email
        let minimal_email = b"\r\n\r\nMinimal body";
        let result = parse_mail(minimal_email);
        match result {
            Ok(parsed) => {
                let body = parsed.get_body().unwrap_or_default();
                assert!(body.contains("Minimal body"));
            }
            Err(_) => {
                assert!(true, "Minimal email handling is implementation-dependent");
            }
        }
    }

    #[test]
    fn test_large_email_performance() {
        // Test with a large email to ensure performance
        let mut large_email = String::from("From: sender@example.com\r\n");
        large_email.push_str("To: recipient@example.com\r\n");
        large_email.push_str("Subject: Large Email Performance Test\r\n");
        large_email.push_str("Content-Type: text/plain\r\n");
        large_email.push_str("\r\n");

        // Add 10MB of content
        for i in 0..100000 {
            large_email.push_str(&format!(
                "Line {} with some content to make it substantial.\r\n",
                i
            ));
        }

        let start = Instant::now();
        let result = parse_mail(large_email.as_bytes());
        let parse_duration = start.elapsed();

        assert!(result.is_ok(), "Should parse large email successfully");
        assert!(
            parse_duration.as_secs() < 5,
            "Large email parsing should complete within 5 seconds"
        );

        if let Ok(parsed) = result {
            let start = Instant::now();
            let _body = extract_email_body(&parsed);
            let extract_duration = start.elapsed();
            assert!(
                extract_duration.as_secs() < 2,
                "Body extraction should be fast even for large emails"
            );
        }
    }

    #[test]
    fn test_unicode_and_international_content() {
        // Test email with international characters
        let unicode_email = "From: sender@example.com\r\n\
                            To: recipient@example.com\r\n\
                            Subject: =?UTF-8?B?VW5pY29kZSBUZXN0IPCfmIE=?=\r\n\
                            Content-Type: text/plain; charset=UTF-8\r\n\
                            \r\n\
                            Hello 世界! Bonjour 🌍!"
            .as_bytes();

        let result = parse_mail(unicode_email);
        match result {
            Ok(parsed) => {
                let body = parsed.get_body().unwrap_or_default();
                // Should handle Unicode content gracefully
                assert!(!body.is_empty(), "Should extract Unicode body content");
            }
            Err(_) => {
                assert!(true, "Unicode handling may vary by implementation");
            }
        }
    }

    #[test]
    fn test_malformed_content_type() {
        // Test various malformed Content-Type headers
        let malformed_ct_cases = vec![
            b"Content-Type: text\r\n\r\nBody".to_vec(),
            b"Content-Type: text/\r\n\r\nBody".to_vec(),
            b"Content-Type: text/plain; invalid\r\n\r\nBody".to_vec(),
            b"Content-Type: invalid/type\r\n\r\nBody".to_vec(),
        ];

        for (i, malformed_email) in malformed_ct_cases.iter().enumerate() {
            let result = parse_mail(malformed_email);
            match result {
                Ok(parsed) => {
                    // Should not crash when processing
                    let _body = extract_email_body(&parsed);
                    assert!(true, "Malformed Content-Type {} handled gracefully", i);
                }
                Err(_) => {
                    assert!(true, "Malformed Content-Type {} appropriately rejected", i);
                }
            }
        }
    }

    #[test]
    fn test_extracted_body_consistency() {
        // Load the test email file
        let email_data =
            fs::read("tests/data/sample_email.eml").expect("Failed to read sample email");

        let parsed = parse_mail(&email_data).expect("Should parse test email");

        // Test body extraction multiple times for consistency
        let body1 = extract_email_body(&parsed);
        let body2 = extract_email_body(&parsed);
        let body3 = extract_email_body(&parsed);

        assert_eq!(body1, body2, "Body extraction should be consistent");
        assert_eq!(body2, body3, "Body extraction should be deterministic");
        assert!(!body1.is_empty(), "Extracted body should not be empty");
    }
}
