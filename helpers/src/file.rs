use anyhow::{anyhow, Result};
use std::{fs::File, io::BufReader, io::Read, path::PathBuf};

pub fn read_email_file(path: &PathBuf) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| anyhow!("Failed to open email file: {}", e))?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = Vec::new();
    buf_reader
        .read_to_end(&mut contents)
        .map_err(|e| anyhow!("Failed to read email contents: {}", e))?;
    Ok(contents)
}

pub fn read_json_file<T>(path: &PathBuf) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let file =
        File::open(path).map_err(|e| anyhow!("Failed to open file {}: {}", path.display(), e))?;

    serde_json::from_reader(file)
        .map_err(|e| anyhow!("Failed to parse JSON from {}: {}", path.display(), e))
}
