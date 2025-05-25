/// Email processing profiler for analyzing performance characteristics
/// of core zkemail operations including parsing, body extraction,
/// DKIM verification, and cryptographic hashing.
use mailparse::{parse_mail, MailHeaderMap};
use slog::{o, Discard, Logger};
use std::fs;
use std::path::Path;
use zkemail_core::{extract_email_body, hash_bytes, verify_dkim, Email, PublicKey};
use zkemail_profiling::{
    cpu_profiler::setup_flamegraph_instructions, profile_cpu_usage, profile_memory_usage,
    setup_memory_profiler,
};

/// Loads test email data from the tests directory.
///
/// # Arguments
/// * `filename` - Name of the email file to load
///
/// # Returns
/// Result containing the file bytes or an error if the file cannot be read
fn load_test_email(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    let path = Path::new("tests").join("data").join(filename);
    fs::read(&path)
}

/// Creates a test email instance for profiling operations.
///
/// # Arguments
/// * `use_dkim_email` - Whether to use a DKIM-signed email for testing
///
/// # Returns
/// An optional `Email` struct configured for testing, or None if required files are missing
fn create_test_email(use_dkim_email: bool) -> Option<Email> {
    let filename = if use_dkim_email {
        "dkim_test_email.eml"
    } else {
        "sample_email.eml"
    };

    let email_data = load_test_email(filename).ok()?;

    // Create a dummy public key for testing when DKIM key file is not available
    let key_data = load_test_email("dkim_public_key.pem")
        .unwrap_or_else(|_| b"dummy-key-for-testing".to_vec());

    Some(Email {
        raw_email: email_data,
        from_domain: "example.org".to_string(),
        public_key: PublicKey {
            key: key_data,
            key_type: "rsa".to_string(),
        },
        external_inputs: vec![],
    })
}

/// Profiles email parsing performance using CPU profiling.
///
/// # Arguments
/// * `email_data` - Raw email bytes to parse
fn profile_email_parsing(email_data: &[u8]) {
    profile_cpu_usage("email_parsing", || {
        let parsed = parse_mail(email_data).expect("Failed to parse email");
        let subject = parsed
            .headers
            .get_first_value("Subject")
            .unwrap_or_default();
        println!("Parsed email subject: {}", subject);
    });
}

/// Profiles email body extraction performance using memory profiling.
///
/// # Arguments
/// * `email_data` - Raw email bytes to process
fn profile_email_body_extraction(email_data: &[u8]) {
    profile_memory_usage("email_body_extraction", || {
        let parsed = parse_mail(email_data).expect("Failed to parse email");
        let body = extract_email_body(&parsed);
        println!("Extracted body size: {} bytes", body.len());
    });
}

/// Profiles DKIM signature verification performance.
///
/// # Arguments
/// * `email` - Email instance with DKIM signature to verify
fn profile_dkim_verification(email: &Email) {
    let logger = Logger::root(Discard, o!());

    profile_cpu_usage("dkim_verification", || {
        let result = verify_dkim(email, &logger);
        println!("DKIM verification result: {}", result);
    });
}

/// Main profiling routine that executes all performance tests.
fn main() {
    setup_memory_profiler();

    println!("Email Processing Profiler");
    println!("========================");

    // Profile standard email processing
    if let Some(regular_email) = create_test_email(false) {
        println!("\nProfiling standard email operations:");
        profile_email_parsing(&regular_email.raw_email);
        profile_email_body_extraction(&regular_email.raw_email);
    } else {
        println!("\nSkipping standard email profiling: test file unavailable");
    }

    // Profile DKIM-enabled email processing
    if let Some(dkim_email) = create_test_email(true) {
        println!("\nProfiling DKIM email operations:");
        profile_email_parsing(&dkim_email.raw_email);
        profile_email_body_extraction(&dkim_email.raw_email);
        profile_dkim_verification(&dkim_email);
    } else {
        println!("\nSkipping DKIM email profiling: test file unavailable");
    }

    // Profile cryptographic hashing
    let sample_text = "Sample text for hash performance analysis";
    profile_cpu_usage("hash_bytes", || {
        let hash_result = hash_bytes(sample_text.as_bytes());
        println!("Hash output size: {} bytes", hash_result.len());
    });

    // Display advanced profiling instructions
    println!("\nAdvanced Profiling Options:");
    println!("==========================");
    println!("{}", setup_flamegraph_instructions());

    println!("\nProfiling session completed.");
    println!("\nExternal memory analysis tools:");
    println!("• Linux (Valgrind Massif): valgrind --tool=massif ./target/release/email_profiler");
    println!("• Linux (Callgrind): valgrind --tool=callgrind ./target/release/email_profiler");
    println!("• Memory leak detection: valgrind --leak-check=full ./target/release/email_profiler");
}
