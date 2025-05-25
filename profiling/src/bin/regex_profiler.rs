/// Regex performance profiler for analyzing pattern matching efficiency
/// in zkemail operations including DFA processing and capture extraction.
use regex_automata::dfa::regex::Regex;
use std::fs;
use std::path::Path;
use zkemail_core::{process_regex_parts, CompiledRegex, DFA};
use zkemail_profiling::{profile_cpu_usage, profile_memory_usage, setup_memory_profiler};

/// Loads compiled regex data from test files.
///
/// # Returns
/// A vector of `CompiledRegex` instances for profiling
///
/// # Panics
/// Panics if test data files cannot be read
fn load_regex_data() -> Vec<CompiledRegex> {
    let fwd_path = Path::new("tests").join("data").join("regex_amount_fwd.bin");
    let bwd_path = Path::new("tests").join("data").join("regex_amount_bwd.bin");
    let fwd_data =
        fs::read(&fwd_path).unwrap_or_else(|_| panic!("Failed to read data at {:?}", fwd_path));
    let bwd_data =
        fs::read(&bwd_path).unwrap_or_else(|_| panic!("Failed to read data at {:?}", bwd_path));

    vec![
        CompiledRegex {
            verify_re: DFA {
                fwd: fwd_data.clone(),
                bwd: bwd_data.clone(),
            },
            captures: Some(vec!["amount".to_string()]),
        },
        CompiledRegex {
            verify_re: DFA {
                fwd: fwd_data,
                bwd: bwd_data,
            },
            captures: Some(vec!["date".to_string()]),
        },
    ]
}

/// Creates test input data containing patterns for regex matching.
///
/// # Returns
/// Byte vector containing sample text with various matchable patterns
fn create_test_input() -> Vec<u8> {
    let sample_text = r#"Test email content with various patterns.
Amount: $123.45 USD
Order #A12345  
Transfer $1,000.00 to account 123-456-7890
Contact: test@example.com
Date: 2024-01-15
"#;
    sample_text.as_bytes().to_vec()
}

/// Profiles regex compilation performance.
fn profile_regex_compilation() {
    profile_memory_usage("regex_compilation", || {
        let pattern = r"[$][\d,]+\.\d{2}";
        let _regex = Regex::new(pattern).expect("Failed to compile regex pattern");
        println!("Compiled pattern: {}", pattern);
    });
}

/// Profiles regex matching performance against test input.
fn profile_regex_matching() {
    let pattern = r"[$][\d,]+\.\d{2}";
    let regex = Regex::new(pattern).expect("Failed to compile regex pattern");
    let input = create_test_input();

    profile_cpu_usage("regex_matching", || {
        let match_count = regex.find_iter(&input).count();
        println!("Pattern matches found: {}", match_count);
    });
}

/// Profiles zkemail-specific regex processing functionality.
fn profile_regex_processing() {
    let regex_parts = load_regex_data();
    let input = create_test_input();

    profile_cpu_usage("process_regex_parts", || {
        let (matched, captures) = process_regex_parts(&regex_parts, &input);
        println!(
            "Processing result - Matched: {}, Captures: {}",
            matched,
            captures.len()
        );
        for (i, capture) in captures.iter().enumerate() {
            println!("  Capture {}: {}", i + 1, capture);
        }
    });
}

/// Profiles compilation and processing of complex regex patterns.
fn profile_complex_regex() {
    let email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}";

    profile_memory_usage("complex_regex_compilation", || {
        match Regex::new(email_pattern) {
            Ok(_regex) => {
                println!("Successfully compiled complex email pattern");
            }
            Err(error) => {
                println!("Failed to compile complex pattern: {}", error);
            }
        }
    });
}

/// Main profiling routine that executes all regex performance tests.
fn main() {
    setup_memory_profiler();

    println!("Regex Performance Profiler");
    println!("==========================");

    println!("\nProfiling regex compilation:");
    profile_regex_compilation();

    println!("\nProfiling regex matching:");
    profile_regex_matching();

    println!("\nProfiling zkemail regex processing:");
    profile_regex_processing();

    println!("\nProfiling complex patterns:");
    profile_complex_regex();

    println!("\nRegex profiling session completed.");
}
