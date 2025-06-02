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

// TODO: remove this when using relayer-utils
/// Removes Quoted-Printable (QP) soft line breaks (`=\r\n`) from the given byte vector while
/// maintaining a mapping from cleaned indices back to the original positions.
///
/// Quoted-printable encoding may split long lines with `=\r\n` sequences. This function removes
/// these soft line breaks, producing a "cleaned" output array. It also creates an index map so
/// that for each position in the cleaned output, you can find the corresponding original index.
///
/// Any positions in the cleaned output that were added as padding (to match the original length)
/// will have their index map entry set to `usize::MAX`, indicating no corresponding original index.
///
/// # Arguments
///
/// * `body` - A `Vec<u8>` containing the QP-encoded content.
///
/// # Returns
///
/// A tuple of:
/// - `Vec<u8>`: The cleaned content, with all QP soft line breaks removed and padded with zeros
///              to match the original length.
/// - `Vec<usize>`: A mapping from cleaned indices to original indices. For cleaned indices that
///                 correspond to actual content, `index_map[i]` gives the original position of
///                 that byte in `body`. For padded bytes, the value is `usize::MAX`.
pub fn remove_quoted_printable_soft_breaks(body: Vec<u8>) -> (Vec<u8>, Vec<usize>) {
    let original_len = body.len();
    let mut cleaned = Vec::with_capacity(original_len);
    let mut index_map = Vec::with_capacity(original_len);

    let mut iter = body.iter().enumerate();
    while let Some((i, &byte)) = iter.next() {
        // Check if this is the start of a soft line break sequence `=\r\n`
        if byte == b'=' && body.get(i + 1..i + 3) == Some(&[b'\r', b'\n']) {
            // Skip the next two bytes for the soft line break
            iter.nth(1);
        } else {
            cleaned.push(byte);
            index_map.push(i);
        }
    }

    // Pad the cleaned result with zeros to match the original length
    cleaned.resize(original_len, 0);

    // Pad index_map with usize::MAX for these padded positions
    let padding_needed = original_len - index_map.len();
    index_map.extend(std::iter::repeat(usize::MAX).take(padding_needed));

    (cleaned, index_map)
}
