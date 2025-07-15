use anyhow::{anyhow, Result};
use regex_automata::{dfa::regex::Regex as DFARegex, meta::Regex as MetaRegex};
use zkemail_core::{CompiledRegex, DFA};

use crate::structs::RegexPattern;

pub fn create_dfa(re: &DFARegex) -> DFA {
    let (fwd, fwd_pad) = re.forward().to_bytes_little_endian();
    let (bwd, bwd_pad) = re.reverse().to_bytes_little_endian();
    DFA {
        fwd: fwd[fwd_pad..].to_vec(),
        bwd: bwd[bwd_pad..].to_vec(),
    }
}

pub fn compile_regex_parts(parts: &[RegexPattern], input: &[u8]) -> Result<Vec<CompiledRegex>> {
    parts
        .iter()
        .map(|part| {
            let verify_dfa_re = DFARegex::new(&part.pattern)?;
            if verify_dfa_re.find_iter(input).count() != 1 {
                return Err(anyhow!("Input doesn't match regex pattern: {:?}", part));
            }

            let verify_meta_re = MetaRegex::new(&part.pattern)?;
            let mut caps = verify_meta_re.create_captures();
            verify_meta_re.captures(input, &mut caps);

            let captured_strings = if let Some(captures) = &part.capture_indices {
                let results: Result<Vec<String>, _> = captures
                    .iter()
                    .map(|i| {
                        caps.get_group(*i)
                            .map(|capture| {
                                String::from_utf8_lossy(&input[capture.range()]).into_owned()
                            })
                            .ok_or_else(|| anyhow!("Capture group not found"))
                    })
                    .collect();
                results?
            } else {
                Vec::new()
            };

            Ok(CompiledRegex {
                verify_re: create_dfa(&verify_dfa_re),
                captures: Some(captured_strings),
            })
        })
        .collect()
}
