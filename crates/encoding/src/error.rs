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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeBase64Error {
    /// The length of a base64 encoded string must be divisible by 4
    InvalidLength,

    /// Attempt to parse a char that does not represent a base64 value
    InvalidBase64Char,
}

impl std::error::Error for DecodeBase64Error {}

impl fmt::Display for DecodeBase64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeBase64Error::InvalidLength => {
                "the length of the input string must be divisible by 4".fmt(f)
            }
            DecodeBase64Error::InvalidBase64Char => {
                "input string contains atleast one invalid character".fmt(f)
            }
        }
    }
}
