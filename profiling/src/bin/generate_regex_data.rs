/// Regex test data generator for creating compiled DFA files
/// used in profiling and testing zkemail regex operations.
use regex_automata::dfa::regex::Regex;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generates compiled regex DFA files for testing and profiling.
///
/// This utility creates forward and backward DFA files for common
/// email patterns used in zkemail operations.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Regex Test Data Generator");
    println!("========================");

    // Generate DFA files for dollar amount pattern
    generate_amount_regex()?;

    // Generate DFA files for transaction ID pattern
    generate_transaction_id_regex()?;

    println!("\nRegex test data generation completed successfully.");
    Ok(())
}

/// Generates DFA files for dollar amount pattern matching.
fn generate_amount_regex() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = r"[$][\d,]+\.\d{2}";
    println!("\nGenerating DFA for amount pattern: {}", pattern);

    let regex = Regex::new(pattern)?;
    let fwd = regex.forward().to_bytes_little_endian();
    let bwd = regex.reverse().to_bytes_little_endian();

    write_dfa_files(&fwd.0, &bwd.0, "regex_amount")?;
    Ok(())
}

/// Generates DFA files for transaction ID pattern matching.
fn generate_transaction_id_regex() -> Result<(), Box<dyn std::error::Error>> {
    let pattern = r"[A-Z0-9]{6,10}";
    println!("\nGenerating DFA for transaction ID pattern: {}", pattern);

    let regex = Regex::new(pattern)?;
    let fwd = regex.forward().to_bytes_little_endian();
    let bwd = regex.reverse().to_bytes_little_endian();

    write_dfa_files(&fwd.0, &bwd.0, "regex_txid")?;
    Ok(())
}

/// Writes forward and backward DFA data to binary files.
///
/// # Arguments
/// * `fwd_data` - Forward DFA binary data
/// * `bwd_data` - Backward DFA binary data  
/// * `prefix` - File name prefix for the output files
fn write_dfa_files(
    fwd_data: &[u8],
    bwd_data: &[u8],
    prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fwd_path = Path::new("tests/data").join(format!("{}_fwd.bin", prefix));
    let bwd_path = Path::new("tests/data").join(format!("{}_bwd.bin", prefix));

    println!("  Writing forward DFA to {:?}", fwd_path);
    let mut fwd_file = File::create(fwd_path)?;
    fwd_file.write_all(fwd_data)?;

    println!("  Writing backward DFA to {:?}", bwd_path);
    let mut bwd_file = File::create(bwd_path)?;
    bwd_file.write_all(bwd_data)?;

    Ok(())
}
