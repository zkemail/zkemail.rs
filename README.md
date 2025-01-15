# ZkEmail.rs

Zero-knowledge proof system for email verification, with support for DKIM signatures and regex pattern matching.

## Installation

```toml
zkemail_core = { git = "https://github.com/zkemail/zkemail.rs" }
zkemail_helpers = { git = "https://github.com/zkemail/zkemail.rs" }
```

### Core (`zkemail_core`)

Low-level library providing:

-   Email verification primitives
-   DKIM signature validation
-   Regex pattern matching
-   Core data structures for email proofs
-   Circuit implementations

### Helpers (`zkemail_helpers`)

High-level utilities for:

-   Email input generation and parsing
-   DNS resolution for DKIM keys
-   Regex compilation and pattern matching
-   Configuration management

## Usage

```rust
use zkemail_core::{verify_email, verify_email_with_regex};
use zkemail_helpers::{generate_email_inputs, generate_email_with_regex_inputs};

// Basic email verification
let email = generate_email_inputs("example.com", "email.txt").await?;
let result = verify_email(&email);

// Email verification with regex matching
let input = generate_email_with_regex_inputs(
    "example.com",
    "email.txt",
    "regex_config.json"
).await?;
let result = verify_email_with_regex(&input);
```
