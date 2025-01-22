mod dkim;
mod email;
mod file;
mod generator;
mod io;
mod regex;
mod structs;

pub use file::{read_email_file, read_regex_config};
pub use generator::{generate_email_inputs, generate_email_with_regex_inputs};
pub use io::*;
pub use structs::*;
