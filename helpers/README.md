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

### Example Regex Config

```json
{
    "header_parts": [
        {
            "prefix": "From: ",
            "capture": ".",
            "suffix": "@gmail\\.com"
        },
        {
            "pattern": "Subject: ."
        }
    ],
    "body_parts": [
        {
            "prefix": "Amount: \\$",
            "capture": "[0-9,]+\\.[0-9]{2}",
            "suffix": "\\s"
        },
        {
            "pattern": "Transaction ID: [A-Z0-9]+"
        }
    ]
}
```

This config:

-   Captures email headers:
    -   Gmail sender address
    -   Full subject line
-   Captures email body:
    -   Dollar amounts (e.g., "$1,234.56")
    -   Transaction IDs
