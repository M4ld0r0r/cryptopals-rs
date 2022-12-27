mod error;
pub use error::*;

use rustcrypto_aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use primitives::xor;

pub static BLOCKSIZE: usize = 16;

/// Block cipher mode of operation
#[derive(Debug, PartialEq)]
pub enum Mode {
    ECB,
    CBC,
}

/// A struct representing an AES128 cipher
#[derive(Debug, PartialEq)]
pub struct Aes128 {
    key: Vec<u8>,
    mode: Mode,
    iv: Option<Vec<u8>>,
}

impl Aes128 {
    /// Creates a new `Aes128` cipher struct
    ///
    /// # Args
    /// `key`: a 16 bytes key
    ///
    /// `mode`: the mode of operation
    ///
    /// `iv`: (optional) the initialization vector
    ///
    /// # Returns
    /// A `Result` wrapping the created `Aes128` struct or an `AesError` in case of failure
    ///
    /// # Examples
    /// ```
    /// use aes::{Aes128, Mode};
    ///
    /// let key = "ABDCDEFGHIJKLHIJ";
    /// let result = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None);
    /// assert_eq!(result.is_ok(), true);
    /// ```
    pub fn new(key: Vec<u8>, mode: Mode, iv: Option<Vec<u8>>) -> Result<Aes128, AesError> {
        if key.len() != 16 {
            return Err(AesError::InvalidKeySizeError);
        }

        if mode == Mode::CBC && iv.is_none() {
            return Err(AesError::IvRequiredError);
        }

        if mode == Mode::CBC && iv.as_ref().unwrap().len() != 16 {
            return Err(AesError::InvalidIvSizeError);
        }

        Ok(Aes128 { key, mode, iv })
    }

    /// Encrypts the given plaintext
    ///
    /// # Args
    /// `plaintext`: The plaintext to encrypt
    ///
    /// # Returns
    /// A `Result` wrapping the output of the encryption or an `AesError`in case of failure
    ///
    /// # Examples
    /// ```
    /// use aes::{Aes128, BLOCKSIZE, Mode};
    /// use primitives::pad_pkcs7;
    ///
    /// let plaintext = "THIS IS A TEST!!".as_bytes();
    /// let key = "abcdefghijkuhgfq";
    ///
    /// let plaintext = &pad_pkcs7(plaintext, BLOCKSIZE).unwrap();
    ///
    /// let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
    /// let result = cipher.encrypt(plaintext).unwrap();
    ///
    /// let expected = [
    ///     0xC8, 0xBC, 0x83, 0xF3, 0x05, 0x4E, 0x99, 0x79, 0xED, 0x6E, 0xB4, 0x37, 0xEB, 0x37,
    ///     0x61, 0x06, 0x78, 0x50, 0x16, 0x2B, 0xDA, 0x24, 0x4F, 0xD5, 0x1B, 0x7F, 0xC7, 0x20,
    ///     0xA1, 0x4E, 0x99, 0x40,
    /// ];
    /// assert_eq!(result, expected);
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
        if plaintext.len() % BLOCKSIZE != 0 {
            return Err(AesError::NotMultipleOfBlockSizeError);
        }

        match self.mode {
            Mode::ECB => {
                Ok(aes_ecb(plaintext, &self.key, false))
            }
            Mode::CBC => {
                Ok(aes_cbc(
                    plaintext,
                    &self.key,
                    self.iv.as_ref().unwrap(),
                    false,
                ))
            }
        }
    }

    /// Decrypts the given ciphertext
    ///
    /// # Args
    /// `ciphertext`: The ciphertext to decrypt
    ///
    /// # Returns
    /// A `Result` wrapping the output of the decryption or an `AesError`in case of failure
    ///
    /// # Examples
    /// ```
    /// use aes::{Aes128, BLOCKSIZE, Mode};
    /// use primitives::pad_pkcs7;
    ///
    /// let ciphertext = [
    ///    0xC8, 0xBC, 0x83, 0xF3, 0x05, 0x4E, 0x99, 0x79, 0xED, 0x6E, 0xB4, 0x37, 0xEB, 0x37,
    ///    0x61, 0x06, 0x78, 0x50, 0x16, 0x2B, 0xDA, 0x24, 0x4F, 0xD5, 0x1B, 0x7F, 0xC7, 0x20,
    ///    0xA1, 0x4E, 0x99, 0x40,
    /// ];
    /// let key = "abcdefghijkuhgfq";
    ///
    /// let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
    /// let result = cipher.decrypt(&ciphertext).unwrap();
    ///
    /// let expected = [
    ///     0x54, 0x48, 0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54,
    ///     0x21, 0x21, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    ///     0x10, 0x10, 0x10, 0x10,
    /// ];
    ///
    /// assert_eq!(result, expected);
    /// ```
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
        if ciphertext.len() % BLOCKSIZE != 0 {
            return Err(AesError::NotMultipleOfBlockSizeError);
        }

        match self.mode {
            Mode::ECB => {
                Ok(aes_ecb(ciphertext, &self.key, true))
            }
            Mode::CBC => {
                Ok(aes_cbc(
                    ciphertext,
                    &self.key,
                    self.iv.as_ref().unwrap(),
                    true,
                ))
            }
        }
    }
}

/// Encrypts/Decrypts the given `text` with the given `key` using AES in ECB mode.
/// The text length must be a multiple of 16
fn aes_ecb(text: &[u8], key: &[u8], decrypt: bool) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let cipher = rustcrypto_aes::Aes128::new(&key);

    let mut blocks = Vec::new();
    text.chunks(BLOCKSIZE).for_each(|x| {
        blocks.push(GenericArray::clone_from_slice(x));
    });

    if decrypt {
        cipher.decrypt_blocks(&mut blocks);
    } else {
        cipher.encrypt_blocks(&mut blocks);
    }

    blocks.iter().flatten().copied().collect()
}

/// Encrypts/Decrypts the given `text` with the given `key` and `iv` using AES in CBC mode.
/// The text length must be a multiple of 16
fn aes_cbc(text: &[u8], key: &[u8], iv: &[u8], decrypt: bool) -> Vec<u8> {
    let mut blocks = Vec::new();

    let mut prev = iv.to_owned();

    text.chunks(BLOCKSIZE).for_each(|chunk| {
        if decrypt {
            let plaintext_block = xor(&prev, &aes_ecb(chunk, key, true));
            blocks.push(plaintext_block);
            prev = chunk.to_vec();
        } else {
            let ciphertext_block = aes_ecb(&xor(chunk, &prev), key, false);
            blocks.push(ciphertext_block.clone());
            prev = ciphertext_block;
        }
    });

    blocks.iter().flatten().copied().collect()
}

#[cfg(test)]
mod tests {
    use primitives::pad_pkcs7;

    use super::*;

    #[test]
    fn aes_new_invalid_key_length() {
        let key = "ABDCDEFGHIJKL"; // len = 13
        let result = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None);
        let expected = Err(AesError::InvalidKeySizeError);
        assert_eq!(result, expected);
    }

    #[test]
    fn aes_new_cbc_no_iv() {
        let key = "ABDCDEFGHIJKLHIJ";
        let result = Aes128::new(key.as_bytes().to_vec(), Mode::CBC, None);
        let expected = Err(AesError::IvRequiredError);
        assert_eq!(result, expected);
    }

    #[test]
    fn aes_new_cbc_invalid_iv_size() {
        let key = "ABDCDEFGHIJKLHIJ";
        let iv = "aA)/SAYDj";
        let result = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        );
        let expected = Err(AesError::InvalidIvSizeError);
        assert_eq!(result, expected);
    }

    #[test]
    fn aes_new_ecb_all_good() {
        let key = "ABDCDEFGHIJKLHIJ";
        let result = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn aes_new_cbc_all_good() {
        let key = "ABDCDEFGHIJKLHIJ";
        let iv = "1234567891234567";
        let result = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        );
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn aes_ecb_encrypt_full_block_padding() {
        let plaintext = "THIS IS A TEST!!".as_bytes();
        let key = "abcdefghijkuhgfq";

        let plaintext = &pad_pkcs7(plaintext, BLOCKSIZE).unwrap();

        let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
        let result = cipher.encrypt(plaintext).unwrap();

        let expected = [
            0xC8, 0xBC, 0x83, 0xF3, 0x05, 0x4E, 0x99, 0x79, 0xED, 0x6E, 0xB4, 0x37, 0xEB, 0x37,
            0x61, 0x06, 0x78, 0x50, 0x16, 0x2B, 0xDA, 0x24, 0x4F, 0xD5, 0x1B, 0x7F, 0xC7, 0x20,
            0xA1, 0x4E, 0x99, 0x40,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_ecb_encrypt_2_bytes_padding() {
        let plaintext = "THIS IS A TEST".as_bytes();
        let key = "abcdefghijkuhgfq";

        let plaintext = &pad_pkcs7(plaintext, BLOCKSIZE).unwrap();

        let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
        let result = cipher.encrypt(plaintext).unwrap();

        let expected = [
            0xF4, 0x02, 0x8B, 0xFE, 0x03, 0xE0, 0x47, 0xBC, 0xFC, 0x8B, 0x98, 0xC9, 0xC0, 0xFA,
            0xED, 0x8E,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_ecb_decrypt() {
        let ciphertext = [
            0xC8, 0xBC, 0x83, 0xF3, 0x05, 0x4E, 0x99, 0x79, 0xED, 0x6E, 0xB4, 0x37, 0xEB, 0x37,
            0x61, 0x06, 0x78, 0x50, 0x16, 0x2B, 0xDA, 0x24, 0x4F, 0xD5, 0x1B, 0x7F, 0xC7, 0x20,
            0xA1, 0x4E, 0x99, 0x40,
        ];
        let key = "abcdefghijkuhgfq";

        let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
        let result = cipher.decrypt(&ciphertext).unwrap();

        let expected = [
            0x54, 0x48, 0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54,
            0x21, 0x21, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_ecb_not_multiple_of_block_size() {
        let plaintext = "THIS IS A TEST".as_bytes();
        let key = "abcdefghijkuhgfq";

        let cipher = Aes128::new(key.as_bytes().to_vec(), Mode::ECB, None).unwrap();
        let result = cipher.encrypt(plaintext);

        let expected = Err(AesError::NotMultipleOfBlockSizeError);

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_cbc_encrypt_full_block_padding() {
        let plaintext = "THIS IS A TEST!!".as_bytes();
        let key = "abcdefghijkuhgfq";
        let iv = "0123456789ABCDEF";

        let plaintext = &pad_pkcs7(plaintext, BLOCKSIZE).unwrap();

        let cipher = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        )
        .unwrap();
        let result = cipher.encrypt(plaintext).unwrap();

        let expected = [
            0xF4, 0x59, 0xDD, 0xDE, 0xC0, 0xC3, 0x57, 0xDC, 0xE5, 0xDF, 0x06, 0xB8, 0x84, 0x97,
            0xD3, 0xF7, 0x0B, 0x92, 0x05, 0xC4, 0x21, 0x4D, 0xD5, 0xFE, 0x1F, 0x1E, 0xE1, 0x1A,
            0x34, 0xA1, 0x4A, 0x77,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_cbc_encrypt_3_blocks() {
        let plaintext = [
            0x54, 0x48, 0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54,
            0x20, 0x57, 0x49, 0x54, 0x48, 0x20, 0x33, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x20,
            0x4F, 0x46, 0x20, 0x4C, 0x45, 0x4E, 0x47, 0x54, 0x48, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        ];
        let key = "abcdefghijkuhgfq";
        let iv = "0123456789ABCDEF";

        let cipher = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        )
        .unwrap();
        let result = cipher.encrypt(&plaintext).unwrap();

        let expected = [
            0x5F, 0x4B, 0x20, 0xD0, 0xE1, 0xA0, 0xCD, 0xC3, 0x4F, 0x45, 0x5F, 0x52, 0xFE, 0x78,
            0x9E, 0xE4, 0x18, 0x12, 0x88, 0xC3, 0x93, 0xC4, 0x27, 0x8E, 0xE3, 0x5D, 0x05, 0xAA,
            0x88, 0x72, 0x55, 0x9A, 0x86, 0x52, 0xB1, 0x83, 0x6A, 0x75, 0x2D, 0xF3, 0xD9, 0xAA,
            0x1A, 0x19, 0x33, 0xE6, 0x88, 0x0F, 0xC8, 0x0A, 0x78, 0x75, 0xD7, 0x38, 0x6D, 0xA3,
            0x59, 0xDD, 0x8E, 0x39, 0x05, 0x26, 0xCA, 0xA0,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_cbc_decrypt_1_block() {
        let ciphertext = [
            0xF4, 0x59, 0xDD, 0xDE, 0xC0, 0xC3, 0x57, 0xDC, 0xE5, 0xDF, 0x06, 0xB8, 0x84, 0x97,
            0xD3, 0xF7, 0x0B, 0x92, 0x05, 0xC4, 0x21, 0x4D, 0xD5, 0xFE, 0x1F, 0x1E, 0xE1, 0x1A,
            0x34, 0xA1, 0x4A, 0x77,
        ];
        let key = "abcdefghijkuhgfq";
        let iv = "0123456789ABCDEF";

        let cipher = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        )
        .unwrap();
        let result = cipher.decrypt(&ciphertext).unwrap();

        let expected = [
            0x54, 0x48, 0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54,
            0x21, 0x21, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn aes_cbc_decrypt_3_blocks() {
        let ciphertext = [
            0x5F, 0x4B, 0x20, 0xD0, 0xE1, 0xA0, 0xCD, 0xC3, 0x4F, 0x45, 0x5F, 0x52, 0xFE, 0x78,
            0x9E, 0xE4, 0x18, 0x12, 0x88, 0xC3, 0x93, 0xC4, 0x27, 0x8E, 0xE3, 0x5D, 0x05, 0xAA,
            0x88, 0x72, 0x55, 0x9A, 0x86, 0x52, 0xB1, 0x83, 0x6A, 0x75, 0x2D, 0xF3, 0xD9, 0xAA,
            0x1A, 0x19, 0x33, 0xE6, 0x88, 0x0F, 0xC8, 0x0A, 0x78, 0x75, 0xD7, 0x38, 0x6D, 0xA3,
            0x59, 0xDD, 0x8E, 0x39, 0x05, 0x26, 0xCA, 0xA0,
        ];
        let key = "abcdefghijkuhgfq";
        let iv = "0123456789ABCDEF";

        let cipher = Aes128::new(
            key.as_bytes().to_vec(),
            Mode::CBC,
            Some(iv.as_bytes().to_vec()),
        )
        .unwrap();
        let result = cipher.decrypt(&ciphertext).unwrap();

        let expected = [
            0x54, 0x48, 0x49, 0x53, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x54, 0x45, 0x53, 0x54,
            0x20, 0x57, 0x49, 0x54, 0x48, 0x20, 0x33, 0x20, 0x42, 0x4C, 0x4F, 0x43, 0x4B, 0x20,
            0x4F, 0x46, 0x20, 0x4C, 0x45, 0x4E, 0x47, 0x54, 0x48, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        ];

        assert_eq!(result, expected);
    }
}
