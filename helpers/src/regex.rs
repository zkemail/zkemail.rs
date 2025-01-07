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
        .map(|part| match part {
            RegexPattern::Match { pattern } => {
                let verify_dfa_re = DFARegex::new(pattern)?;
                if verify_dfa_re.find_iter(input).count() != 1 {
                    return Err(anyhow!("Input doesn't match regex pattern: {:?}", part));
                }

                Ok(CompiledRegex {
                    verify_re: create_dfa(&verify_dfa_re),
                    capture_str: None,
                })
            }
            RegexPattern::Capture {
                prefix,
                capture,
                suffix,
            } => {
                let pattern_dfa = format!("{}{}{}", prefix, capture, suffix);
                let pattern_meta = format!("({})({})({})", prefix, capture, suffix);

                let verify_dfa_re = DFARegex::new(&pattern_dfa)?;
                if verify_dfa_re.find_iter(input).count() != 1 {
                    return Err(anyhow!("Input doesn't match regex pattern: {:?}", part));
                }

                let verify_meta_re = MetaRegex::new(&pattern_meta)?;
                let mut caps = verify_meta_re.create_captures();
                verify_meta_re.captures(input, &mut caps);

                let capture_str = caps
                    .get_group(2)
                    .and_then(|capture| String::from_utf8(input[capture.range()].to_vec()).ok())
                    .ok_or_else(|| anyhow!("Capture contains invalid UTF-8 data"))?;

                Ok(CompiledRegex {
                    verify_re: create_dfa(&verify_dfa_re),
                    capture_str: Some(capture_str),
                })
            }
        })
        .collect()
}
