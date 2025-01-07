mod email;
mod file;
mod generator;
mod regex;
mod structs;

pub use generator::{generate_email_inputs, generate_email_with_regex_inputs};
pub use structs::*;
