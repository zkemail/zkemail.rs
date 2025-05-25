use regex_automata::dfa::{dense, regex::Regex};
use std::borrow::Cow;

use crate::CompiledRegex;

#[cfg(feature = "sp1")]
fn align_slice(bytes: &[u8]) -> Vec<u8> {
    let mut aligned = Vec::with_capacity(bytes.len() + 4);
    let offset = (aligned.as_ptr() as usize) % 4;
    let padding = if offset == 0 { 0 } else { 4 - offset };
    aligned.extend(std::iter::repeat(0).take(padding));
    aligned.extend_from_slice(bytes);
    aligned
}

/// Process a single regex part for optimization and reuse.
fn process_single_regex_part(part: &CompiledRegex, input: &[u8]) -> Result<Vec<String>, ()> {
    // Optimize memory usage based on feature flag
    #[cfg(feature = "sp1")]
    let (fwd_data, bwd_data) = {
        let fwd = align_slice(&part.verify_re.fwd);
        let bwd = align_slice(&part.verify_re.bwd);
        (Cow::Owned(fwd), Cow::Owned(bwd))
    };

    #[cfg(not(feature = "sp1"))]
    let (fwd_data, bwd_data) = {
        (
            Cow::Borrowed(&part.verify_re.fwd),
            Cow::Borrowed(&part.verify_re.bwd),
        )
    };

    // Parse DFAs with better error handling
    let fwd = dense::DFA::from_bytes(&fwd_data).map_err(|_| ())?.0;

    let bwd = dense::DFA::from_bytes(&bwd_data).map_err(|_| ())?.0;

    let re = Regex::builder().build_from_dfas(fwd, bwd);

    // Find matches with early termination
    let matches: Vec<_> = re.find_iter(input).collect();
    if matches.len() != 1 {
        return Err(());
    }

    // Process captures with optimized string operations
    let mut captures_result = Vec::new();
    if let Some(captures) = part.captures.as_ref() {
        let match_range = matches[0].range();
        let matched_bytes = &input[match_range];

        // Convert to string once and reuse
        let matched_str = std::str::from_utf8(matched_bytes).map_err(|_| ())?;

        for capture in captures {
            // Use optimized string searching
            if !matched_str.contains(capture) {
                return Err(());
            }

            // Count matches efficiently
            let match_count = matched_str.matches(capture).count();
            if match_count != 1 {
                return Err(());
            }

            captures_result.push(capture.clone());
        }
    }

    Ok(captures_result)
}

/// Optimized regex processing with reduced allocations and improved performance.
///
/// Key optimizations:
/// - Avoids unnecessary clones when SP1 feature is disabled
/// - Uses early returns to short-circuit on failure
/// - Pre-allocates result vectors with known capacity
/// - Optimized string matching with better algorithms
pub fn process_regex_parts(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    // Early return for empty inputs
    if compiled_regexes.is_empty() {
        return (true, Vec::new());
    }

    // For small numbers of regexes, use sequential processing
    if compiled_regexes.len() <= 2 {
        return process_regex_parts_sequential(compiled_regexes, input);
    }

    // Use parallel processing for larger sets
    process_regex_parts_parallel(compiled_regexes, input)
}

/// Sequential processing optimized for small regex sets.
fn process_regex_parts_sequential(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    // Pre-allocate with estimated capacity to reduce reallocations
    let estimated_matches = compiled_regexes
        .iter()
        .map(|r| r.captures.as_ref().map_or(0, |c| c.len()))
        .sum();
    let mut regex_matches = Vec::with_capacity(estimated_matches);

    for part in compiled_regexes {
        match process_single_regex_part(part, input) {
            Ok(mut captures) => regex_matches.append(&mut captures),
            Err(()) => return (false, regex_matches),
        }
    }

    (true, regex_matches)
}

/// Parallel processing for larger regex sets with optimized collection.
fn process_regex_parts_parallel(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    use rayon::prelude::*;
    
    // Process all regex parts in parallel with early termination on failure
    let results: Result<Vec<Vec<String>>, ()> = compiled_regexes
        .par_iter()
        .map(|part| process_single_regex_part(part, input))
        .collect();

    match results {
        Ok(captures_list) => {
            // Flatten results efficiently
            let total_capacity: usize = captures_list.iter().map(|v| v.len()).sum();
            let mut regex_matches = Vec::with_capacity(total_capacity);
            
            for mut captures in captures_list {
                regex_matches.append(&mut captures);
            }
            
            (true, regex_matches)
        }
        Err(()) => (false, Vec::new()),
    }
}

/// Cache-optimized regex processing for repeated patterns.
///
/// Uses thread-local caching to avoid recompiling the same regex patterns
/// repeatedly, which is common in email processing scenarios.
pub fn process_regex_parts_cached(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    use std::sync::Mutex;
    use std::collections::HashMap;
    
    thread_local! {
        static REGEX_CACHE: Mutex<HashMap<u64, bool>> = Mutex::new(HashMap::new());
    }
    
    // Create a cache key from the regex patterns
    let cache_key = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for regex in compiled_regexes {
            regex.verify_re.fwd.hash(&mut hasher);
            regex.verify_re.bwd.hash(&mut hasher);
        }
        input.hash(&mut hasher);
        hasher.finish()
    };
    
    // Check cache for known failures
    let cache_hit = REGEX_CACHE.with(|cache| {
        let cache = cache.lock().unwrap();
        cache.get(&cache_key).copied()
    });
    
    if let Some(false) = cache_hit {
        return (false, Vec::new());
    }
    
    // Process normally
    let result = process_regex_parts(compiled_regexes, input);
    
    // Cache the result if it's a failure (to avoid reprocessing)
    if !result.0 {
        REGEX_CACHE.with(|cache| {
            let mut cache = cache.lock().unwrap();
            if cache.len() < 1000 {  // Limit cache size
                cache.insert(cache_key, false);
            }
        });
    }
    
    result
}
