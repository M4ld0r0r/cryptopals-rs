use std::fmt;

mod error;
pub use crate::error::*;

/// Types that can be decoded from a hexadecimal string
pub trait FromHex: Sized {
    /// Converts the given hexadecimal string to an instance of type `Self`.
    ///
    /// Both lower-case an upper-case letters are supported.
    ///
    /// # Parameters
    ///
    /// `s`: An hexadecimal string
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    ///
    /// - `Ok`: A `Self` value representing the result of the decoding
    /// - `Err`: A `DecodeHexError`. Only happens if the input data is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use encoding::FromHex;
    ///
    /// let result = Vec::from_hex("1a3d44").unwrap();
    /// assert_eq!(result, vec![26, 61, 68]);
    /// ```
    fn from_hex(s: &str) -> Result<Self, DecodeHexError>;
}

impl FromHex for Vec<u8> {
    fn from_hex(s: &str) -> Result<Self, DecodeHexError> {
        if s.len() % 2 != 0 {
            return Err(DecodeHexError::OddLength);
        }

        let mut bytes = Vec::with_capacity(s.len() / 2);

        for i in (0..s.len()).step_by(2) {
            match u8::from_str_radix(&s[i..i + 2], 16) {
                Ok(b) => bytes.push(b),
                _ => {
                    return Err(DecodeHexError::InvalidHexChar);
                }
            }
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_from_hex_correct_input() {
        let result = Vec::from_hex("1a3d44").unwrap();
        let expected = vec![26, 61, 68];
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_from_hex_odd_length() {
        let result = Vec::from_hex("a4b5h");
        let expected = Err(DecodeHexError::OddLength);
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_from_hex_invalid_byte() {
        let result = Vec::from_hex("bb7do7");
        let expected = Err(DecodeHexError::InvalidHexChar);
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_from_hex_empty() {
        let result = Vec::from_hex("").unwrap();
        assert_eq!(result, vec![])
    }
}
