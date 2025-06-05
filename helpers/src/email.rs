use anyhow::{anyhow, Result};

#[allow(dead_code)]
pub fn extract_email_body(email: &mailparse::ParsedMail) -> Result<Vec<u8>> {
    if email.subparts.is_empty() {
        return email.get_body_raw().map_err(Into::into);
    }

    email
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .or_else(|| email.subparts.first())
        .ok_or_else(|| anyhow!("No valid email body found"))?
        .get_body_raw()
        .map_err(Into::into)
}
