#[cfg(test)]
mod regex_tests {
    use regex_automata::dfa::{dense, regex::Regex};
    use std::fs;
    use std::time::{Duration, Instant};
    use zkemail_core::{process_regex_parts, CompiledRegex, DFA};

    // Load regex test data
    fn load_regex_data() -> Vec<CompiledRegex> {
        vec![
            CompiledRegex {
                verify_re: DFA {
                    fwd: fs::read("tests/data/regex_amount_fwd.bin")
                        .expect("Failed to read amount regex forward DFA"),
                    bwd: fs::read("tests/data/regex_amount_bwd.bin")
                        .expect("Failed to read amount regex backward DFA"),
                },
                captures: Some(vec!["$1,234.56".to_string()]),
            },
            CompiledRegex {
                verify_re: DFA {
                    fwd: fs::read("tests/data/regex_txid_fwd.bin")
                        .expect("Failed to read txid regex forward DFA"),
                    bwd: fs::read("tests/data/regex_txid_bwd.bin")
                        .expect("Failed to read txid regex backward DFA"),
                },
                captures: Some(vec!["ABC123XYZ".to_string()]),
            },
        ]
    }

    #[test]
    fn test_regex_basic_matching() {
        let regex_parts = load_regex_data();

        // Test with both patterns in one input
        let input = b"Amount: $1,234.56, ID: ABC123XYZ";

        let start = Instant::now();
        let (is_match, captures) = process_regex_parts(&regex_parts, input);
        let elapsed = start.elapsed();

        assert!(is_match, "Should match both patterns");
        assert_eq!(captures.len(), 2, "Should have two captures");
        assert_eq!(
            captures[0], "$1,234.56",
            "First capture should be the amount"
        );
        assert_eq!(captures[1], "ABC123XYZ", "Second capture should be the ID");

        assert!(
            elapsed < Duration::from_millis(20),
            "Basic regex matching took too long: {:?}",
            elapsed
        );
        // Performance threshold may require adjustment based on environment
    }

    #[test]
    fn test_regex_performance_with_html() {
        let regex_parts = load_regex_data();
        let html_input = b"<html><body><p>This is an HTML email with <strong>$1,234.56</strong> and transaction ID <code>ABC123XYZ</code></p></body></html>";

        let start = Instant::now();
        let _ = process_regex_parts(&regex_parts, html_input);
        let duration = start.elapsed();

        println!("HTML regex matching took: {:?}", duration);
        // Performance threshold may require adjustment based on environment
        assert!(
            duration.as_micros() < 500,
            "HTML regex matching should be under 500µs"
        );
    }

    #[test]
    fn test_regex_performance_with_large_input() {
        let regex_parts = load_regex_data();

        // Create a large input with the pattern repeated many times
        let base_input = b"Amount: $1,234.56, ID: ABC123XYZ. ";
        let mut large_input = Vec::with_capacity(base_input.len() * 1000);
        for _ in 0..1000 {
            large_input.extend_from_slice(base_input);
        }

        let start = Instant::now();
        let _ = process_regex_parts(&regex_parts, &large_input);
        let duration = start.elapsed();

        println!("Large input regex matching took: {:?}", duration);
        // Performance threshold may require adjustment based on environment
        assert!(
            duration.as_millis() < 100,
            "Large input regex matching should be under 100ms"
        );
    }

    #[test]
    fn test_dfa_loading_performance() {
        let fwd_data = fs::read("tests/data/regex_amount_fwd.bin")
            .expect("Failed to read amount regex forward DFA");
        let bwd_data = fs::read("tests/data/regex_amount_bwd.bin")
            .expect("Failed to read amount regex backward DFA");

        let start = Instant::now();
        let fwd = dense::DFA::from_bytes(&fwd_data).unwrap().0;
        let bwd = dense::DFA::from_bytes(&bwd_data).unwrap().0;
        let _ = Regex::builder().build_from_dfas(fwd, bwd);
        let duration = start.elapsed();

        println!("DFA loading took: {:?}", duration);
        // Performance threshold may require adjustment based on environment
        assert!(
            duration.as_micros() < 1000,
            "DFA loading should be under 1ms"
        );
    }

    #[test]
    fn test_regex_with_varying_complexity() {
        // Load just the amount regex
        let amount_regex = vec![CompiledRegex {
            verify_re: DFA {
                fwd: fs::read("tests/data/regex_amount_fwd.bin")
                    .expect("Failed to read amount regex forward DFA"),
                bwd: fs::read("tests/data/regex_amount_bwd.bin")
                    .expect("Failed to read amount regex backward DFA"),
            },
            captures: Some(vec!["$1,234.56".to_string()]),
        }];

        // Test with inputs of varying complexity
        let inputs = [
            b"Simple amount: $123.45".to_vec(),
            b"Multiple amounts: $123.45, $1,234.56, $12,345.67".to_vec(),
            b"Complex with no matches: This text has no dollar amounts at all".to_vec(),
            b"Almost matches: 123.45, 1,234.56 (no dollar signs)".to_vec(),
        ];

        for (i, input) in inputs.iter().enumerate() {
            let start = Instant::now();
            let (is_match, _captures) = process_regex_parts(&amount_regex, input);
            let duration = start.elapsed();

            println!(
                "Input {} regex matching took: {:?}, matches: {}",
                i, duration, is_match
            );
        }
    }
}
