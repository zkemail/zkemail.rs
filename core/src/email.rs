use cfdkim::{verify_email_with_key, DkimPublicKey};
use mailparse::{parse_mail, ParsedMail};
use slog::Logger;

use crate::Email;

pub fn extract_email_body(parsed_email: &ParsedMail) -> Vec<u8> {
    parsed_email
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
        .map_or_else(
            || {
                parsed_email
                    .subparts
                    .first()
                    .map_or(parsed_email.get_body_raw().unwrap(), |part| {
                        part.get_body_raw().unwrap()
                    })
            },
            |part| part.get_body_raw().unwrap(),
        )
}

pub fn verify_dkim(input: &Email, logger: &Logger) -> bool {
    let parsed_email = parse_mail(&input.raw_email).unwrap();

    let public_key =
        DkimPublicKey::try_from_bytes(&input.public_key.key, &input.public_key.key_type).unwrap();

    let result =
        verify_email_with_key(logger, &input.from_domain, &parsed_email, public_key, false)
            .unwrap();

    result.with_detail().starts_with("pass")
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
///   to match the original length.
/// - `Vec<usize>`: A mapping from cleaned indices to original indices. For cleaned indices that
///   correspond to actual content, `index_map[i]` gives the original position of
///   that byte in `body`. For padded bytes, the value is `usize::MAX`.
pub fn remove_quoted_printable_soft_breaks(body: Vec<u8>) -> (Vec<u8>, Vec<usize>) {
    let original_len = body.len();
    let mut cleaned = Vec::with_capacity(original_len);
    let mut index_map = Vec::with_capacity(original_len);

    let mut iter = body.iter().enumerate();
    while let Some((i, &byte)) = iter.next() {
        // Check if this is the start of a soft line break sequence `=\r\n`
        if byte == b'=' && body.get(i + 1..i + 3) == Some(b"\r\n") {
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
