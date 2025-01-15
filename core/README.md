## zkemail_core

### Core API

```rust
// Email verification
fn verify_email(email: &Email) -> EmailVerifierOutput;

// Email verification with regex pattern matching
fn verify_email_with_regex(input: &EmailWithRegex) -> EmailWithRegexVerifierOutput;
```
