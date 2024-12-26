## zkemail_helpers

### Helpers API

```rust
// Generate email verification inputs
async fn generate_email_inputs(
    from_domain: &str,
    email_path: &PathBuf
) -> Result<Email>;

// Generate email + regex verification inputs
async fn generate_email_with_regex_inputs(
    from_domain: &str,
    email_path: &PathBuf,
    config_path: &PathBuf
) -> Result<EmailWithRegex>;
```
