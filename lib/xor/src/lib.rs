/// Performs a XOR operation on the given text with the given key
///
/// # Returns
///
/// A `Vec<u8>` with the result of the xor operation. If either the plaintext or the key is empty, returns an empty `Vec<u8>`
///
/// # Examples
/// ```
/// use crate::xor::xor;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_xor() {
        let input = String::from("hello single byte xor");
        let key = String::from("b");
        let result = xor(input.as_bytes(), key.as_bytes());
        let expected = vec![
            0x0A, 0x07, 0x0E, 0x0E, 0x0D, 0x42, 0x11, 0x0B, 0x0C, 0x05, 0x0E, 0x07, 0x42, 0x00,
            0x1B, 0x16, 0x07, 0x42, 0x1A, 0x0D, 0x10,
        ];
        assert_eq!(result, expected);
    }

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

    // EMPTY inputS AND KEYS!!!!!!!
}
