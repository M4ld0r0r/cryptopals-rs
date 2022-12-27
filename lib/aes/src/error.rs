use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesError {
    InvalidBlockSizeError,
    InvalidIvSizeError,
    InvalidKeySizeError,
    IvRequiredError,
    NotMultipleOfBlockSizeError,
}

impl std::error::Error for AesError {}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AesError::InvalidBlockSizeError => "An AES block must have 16 bytes of length".fmt(f),
            AesError::InvalidIvSizeError => "The size of the IV must be 16 bytes".fmt(f),
            AesError::InvalidKeySizeError => "The key size must be 128, 192 or 256 bits".fmt(f),
            AesError::IvRequiredError => "This mode of operation requires an IV".fmt(f),
            AesError::NotMultipleOfBlockSizeError => {
                "The size of the input text mut be multiple of 16".fmt(f)
            }
        }
    }
}
