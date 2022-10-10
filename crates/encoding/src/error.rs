use std::fmt;

/// Errors that can occur while decoding hexadecimal strings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeHexError {
    /// An hexadecimal string must have an even length
    OddLength,

    /// Attempt to parse a char that does not represent an hexadecimal value
    InvalidHexChar,
}

impl std::error::Error for DecodeHexError {}

impl fmt::Display for DecodeHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeHexError::OddLength => "input string has an odd number of bytes".fmt(f),
            DecodeHexError::InvalidHexChar => {
                "input string contains atleast one invalid character".fmt(f)
            }
        }
    }
}
