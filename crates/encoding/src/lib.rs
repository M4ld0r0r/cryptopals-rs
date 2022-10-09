// mod.rs ????

// different modules ?? (mod.rs) (errors, etc)

// DOCUMENTATION COMMENTS!!!

use std::fmt;

type Bytes = Vec<u8>;

pub trait FromHex {
    fn from_hex(s: &str) -> Result<Bytes, DecodeHexError>;
}

impl FromHex for Bytes {
    fn from_hex(s: &str) -> Result<Bytes, DecodeHexError> {
        if s.len() % 2 != 0 {
            return Err(DecodeHexError::OddLength);
        }

        let mut bytes = Vec::with_capacity(s.len() / 2);

        for i in (0..s.len()).step_by(2) {
            match u8::from_str_radix(&s[i..i + 2], 16) {
                Ok(b) => bytes.push(b),
                _ => {
                    return Err(DecodeHexError::InvalidByte);
                }
            }
        }

        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeHexError {
    OddLength,
    InvalidByte,
}

impl fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeHexError::OddLength => "input string has an odd number of bytes".fmt(f),
            DecodeHexError::InvalidByte => "input string contains one or more invalid bytes".fmt(f),
        }
    }
}

impl std::error::Error for DecodeHexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_from_hex_correct_input() {
        let result = Bytes::from_hex("1a3d44").unwrap();
        let expected = vec![26, 61, 68];
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_from_hex_odd_length() {
        let result = Bytes::from_hex("a4b5h");
        let expected = Err(DecodeHexError::OddLength);
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_from_hex_invalid_byte() {
        let result = Bytes::from_hex("bb7do7");
        let expected = Err(DecodeHexError::InvalidByte);
        assert_eq!(result, expected);
    }
}
