use crate::DecodeBase64Error;

/// Converts a byte to a tuple of hex nibbles
pub fn byte_to_nibbles(byte: &u8) -> (char, char) {
    (
        char::from_digit(u32::from(byte >> 4), 16).unwrap(),
        char::from_digit(u32::from(byte & 0x0F), 16).unwrap(),
    )
}

/// Converts a block of 3 bytes to an iterator with 4 base64 encoded characters
pub fn block_to_base64(block: &[u8]) -> Vec<char> {
    let mut b64_chars = Vec::with_capacity(4);

    let (a, b, c) = match block.len() {
        3 => (block[0], block[1], block[2]),
        2 => (block[0], block[1], 0),
        1 => (block[0], 0, 0),
        _ => return vec![],
    };

    // first 6 bits of a
    b64_chars.push(u8_to_base64(a >> 2));

    // last 2 bits of a followed by the first 4 bits of b
    b64_chars.push(u8_to_base64(a % 4 * 16 + (b >> 4)));

    // last 4 bits of b followed by the first 2 bits of c
    b64_chars.push(u8_to_base64(b % 16 * 4 + (c >> 6)));

    // last 6 bits of c
    b64_chars.push(u8_to_base64(c & 0x3f));

    b64_chars
}

/// Converts a base64 char to it's digit value as a byte
pub fn base64_char_to_u8(c: char) -> Result<u8, DecodeBase64Error> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(26 + (c as u8 - b'a')),
        '0'..='9' => Ok(52 + (c as u8 - b'0')),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(DecodeBase64Error::InvalidBase64Char),
    }
}

/// Converts a u8 representing a base64 sextet to the respective base64 representation
fn u8_to_base64(u: u8) -> char {
    match u {
        0..=25 => (b'A' + u) as char,
        26..=51 => (b'a' + (u - 26)) as char,
        52..=61 => (b'0' + (u - 52)) as char,
        62 => '=',
        63 => '/',
        _ => panic!("byte exceeded range for base64 conversion: {}", u),
    }
}
