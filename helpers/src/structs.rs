use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum RegexPattern {
    Capture {
        prefix: String,
        capture: String,
        suffix: String,
    },
    Match {
        pattern: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegexConfig {
    pub header_parts: Option<Vec<RegexPattern>>,
    pub body_parts: Option<Vec<RegexPattern>>,
}
