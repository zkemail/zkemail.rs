use anyhow::{anyhow, Result};
use std::{fs::File, io::Read, path::PathBuf};

use crate::structs::RegexConfig;

pub fn read_email_file(path: &PathBuf) -> Result<Vec<u8>> {
    use std::io::BufReader;
    let file = File::open(path).map_err(|e| anyhow!("Failed to open email file: {}", e))?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = Vec::new();
    buf_reader
        .read_to_end(&mut contents)
        .map_err(|e| anyhow!("Failed to read email contents: {}", e))?;
    Ok(contents)
}

pub fn read_regex_config(path: &PathBuf) -> Result<RegexConfig> {
    let file = File::open(path).map_err(|e| anyhow!("Failed to open regex config file: {}", e))?;
    let config: RegexConfig =
        serde_json::from_reader(file).map_err(|e| anyhow!("Failed to read regex config: {}", e))?;
    Ok(config)
}
