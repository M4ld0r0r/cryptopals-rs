mod error;
pub use error::*;

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
    if block_size > 255 || block_size <= 0 {
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
