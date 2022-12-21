use std::fmt;

/// Errors that can occur while decoding hexadecimal strings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBlockSizeError;

impl std::error::Error for InvalidBlockSizeError {}

impl fmt::Display for InvalidBlockSizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "the block size must not exceed 255 bytes and must greater than 0".fmt(f)
    }
}
