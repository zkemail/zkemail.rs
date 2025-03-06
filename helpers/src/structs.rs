use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexPattern {
    pub pattern: String,
    pub capture_indices: Option<Vec<usize>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexConfig {
    pub header_parts: Option<Vec<RegexPattern>>,
    pub body_parts: Option<Vec<RegexPattern>>,
}
