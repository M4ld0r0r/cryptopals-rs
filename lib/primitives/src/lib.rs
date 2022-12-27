mod error;
pub use error::*;

/// Performs a XOR operation on the given text with the given key
///
/// # Returns
///
/// A `Vec<u8>` with the result of the xor operation. If either the plaintext or the key is empty, returns an empty `Vec<u8>`
///
/// # Examples
/// ```
/// use primitives::xor;
///
/// let input = String::from("hello repeating key xor");
/// let key = String::from("xor_this");
/// let result = xor(input.as_bytes(), key.as_bytes());
/// let expected = vec![
///     0x10, 0x0A, 0x1E, 0x33, 0x1B, 0x48, 0x1B, 0x16, 0x08, 0x0A, 0x13, 0x2B, 0x1D, 0x06,
///     0x0E, 0x53, 0x13, 0x0A, 0x0B, 0x7F, 0x0C, 0x07, 0x1B,
/// ];
/// assert_eq!(result, expected);
/// ```
pub fn xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let xor = |(d, k)| d ^ k;
    let key = key.iter().cycle();

    input.iter().zip(key).map(xor).collect()
}

/// Adds padding bytes to the given text according to PKCS#7 padding rules
///
/// # Args
/// `text`: the text to be padded
///
/// `block_size`: the block size to pad to
///
/// # Returns
/// A `Vec<u8>` with the padded text or an InvalidBlockSizeError if `block_size` is
/// less than or equal to 0 or greater than 255
///
/// # Examples
///
/// ```
/// use primitives::pad_pkcs7;
///
/// let text: [u8; 12] = [
/// 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
/// ];
/// let result = pad_pkcs7(&text, 16).unwrap();
/// let expected: [u8; 16] = [
///     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x04, 0x04,
///     0x04, 0x04,
/// ];
/// assert_eq!(result, expected);
/// ```
pub fn pad_pkcs7(text: &[u8], block_size: usize) -> Result<Vec<u8>, InvalidBlockSizeError> {
    if block_size > 255 || block_size == 0 {
        return Err(InvalidBlockSizeError);
    }

    let mut out = text.to_owned();

    let padding_size = block_size - text.len() % block_size;
    let padding_byte = padding_size as u8;

    for _ in 0..padding_size {
        out.push(padding_byte);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    static BLOCK_SIZE: usize = 16;

    #[test]
    fn repeating_key_xor_smaller_key() {
        let input = String::from("hello repeating key xor");
        let key = String::from("xor_this");
        let result = xor(input.as_bytes(), key.as_bytes());
        let expected = vec![
            0x10, 0x0A, 0x1E, 0x33, 0x1B, 0x48, 0x1B, 0x16, 0x08, 0x0A, 0x13, 0x2B, 0x1D, 0x06,
            0x0E, 0x53, 0x13, 0x0A, 0x0B, 0x7F, 0x0C, 0x07, 0x1B,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn repeating_key_xor_key_same_length() {
        let input = String::from("hello repeating key xor");
        let key = String::from("976b3_$_sfyu3$7%%%ad3df");
        let result = xor(input.as_bytes(), key.as_bytes());
        let expected = vec![
            0x51, 0x52, 0x5A, 0x0E, 0x5C, 0x7F, 0x56, 0x3A, 0x03, 0x03, 0x18, 0x01, 0x5A, 0x4A,
            0x50, 0x05, 0x4E, 0x40, 0x18, 0x44, 0x4B, 0x0B, 0x14,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn repeating_key_xor_bigger_key() {
        let input = String::from("hello repeating key xor");
        let key = String::from("97fa6874326EB_SD93B9Sugsadi38d23#");
        let result = xor(input.as_bytes(), key.as_bytes());
        let expected = vec![
            0x51, 0x52, 0x0A, 0x0D, 0x59, 0x18, 0x45, 0x51, 0x43, 0x57, 0x57, 0x31, 0x2B, 0x31,
            0x34, 0x64, 0x52, 0x56, 0x3B, 0x19, 0x2B, 0x1A, 0x15,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn pkcs7_padding_empty_block() {
        let text = vec![];
        let result = pad_pkcs7(&text, BLOCK_SIZE).unwrap();
        let expected: [u8; 16] = [
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn pkcs7_padding_full_block() {
        let text: [u8; 16] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66,
        ];
        let result = pad_pkcs7(&text, BLOCK_SIZE).unwrap();
        let expected: [u8; 32] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn pkcs7_padding_4_padding_bytes() {
        let text: [u8; 12] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ];
        let result = pad_pkcs7(&text, BLOCK_SIZE).unwrap();
        let expected: [u8; 16] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x04, 0x04,
            0x04, 0x04,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn pkcs7_padding_15_padding_bytes() {
        let text: [u8; 1] = [0x66];
        let result = pad_pkcs7(&text, BLOCK_SIZE).unwrap();
        let expected: [u8; 16] = [
            0x66, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn pkcs7_padding_1_padding_bytes() {
        let text: [u8; 15] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66,
        ];
        let result = pad_pkcs7(&text, BLOCK_SIZE).unwrap();
        let expected: [u8; 16] = [
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x01,
        ];
        assert_eq!(result, expected);
    }
}
