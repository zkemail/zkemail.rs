use regex_automata::dfa::{dense, regex::Regex};

use crate::CompiledRegex;

#[cfg(feature = "sp1")]
fn align_slice(bytes: &[u8]) -> Vec<u8> {
    let mut aligned = Vec::with_capacity(bytes.len() + 4);
    let offset = (aligned.as_ptr() as usize) % 4;
    let padding = vec![0; if offset == 0 { 0 } else { 4 - offset }];
    aligned.extend_from_slice(&padding);
    aligned.extend_from_slice(bytes);
    aligned
}

pub fn process_regex_parts(
    compiled_regexes: &[CompiledRegex],
    input: &[u8],
) -> (bool, Vec<String>) {
    let capture_count = compiled_regexes
        .iter()
        .filter(|r| r.capture_str.is_some())
        .count();
    let mut regex_matches = Vec::with_capacity(capture_count);

    for part in compiled_regexes {
        #[cfg(feature = "sp1")]
        let fwd = align_slice(&part.verify_re.fwd);
        #[cfg(not(feature = "sp1"))]
        let fwd = part.verify_re.fwd.clone();

        #[cfg(feature = "sp1")]
        let bwd = align_slice(&part.verify_re.bwd);
        #[cfg(not(feature = "sp1"))]
        let bwd = part.verify_re.bwd.clone();

        let fwd = dense::DFA::from_bytes(&fwd).unwrap().0;
        let bwd = dense::DFA::from_bytes(&bwd).unwrap().0;
        let re = Regex::builder().build_from_dfas(fwd, bwd);

        let matches: Vec<_> = re.find_iter(input).collect();
        if matches.len() != 1 {
            return (false, regex_matches);
        }

        if let Some(capture_str) = &part.capture_str {
            let matched_str = std::str::from_utf8(&input[matches[0].range()]).unwrap();
            if !matched_str.contains(capture_str) || matched_str.matches(capture_str).count() != 1 {
                return (false, regex_matches);
            }
            regex_matches.push(capture_str.to_string());
        }
    }

    (true, regex_matches)
}
