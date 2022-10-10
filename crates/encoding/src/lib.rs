mod error;
pub use crate::error::*;

/// Types that can hold the result of hexadecimal and base64 decoding
pub trait Decode: Sized {
    /// Converts the given hexadecimal string to an instance of type `Self`.
    ///
    /// Both lower-case an upper-case letters are supported.
    ///
    /// # Examples
    ///
    /// ```
    /// use encoding::Decode;
    ///
    /// let result = Vec::from_hex("1a3d44").unwrap();
    /// assert_eq!(result, vec![26, 61, 68]);
    /// ```
    fn from_hex(s: &str) -> Result<Self, DecodeHexError>;
}

impl Decode for Vec<u8> {
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

/// Types that can be encoded to hexadecimal and base64
pub trait Encode {
    /// Encodes the given type into a base64 string
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::encoding::Encode;
    ///
    /// let input = vec![108, 105, 103, 104, 116, 32, 119, 111, 114, 107];
    /// let result = input.to_base64();
    /// assert_eq!(result, String::from("bGlnaHQgd29yaw=="));
    /// ```
    fn to_base64(&self) -> String;
}

impl Encode for Vec<u8> {
    fn to_base64(&self) -> String {
        let mut base64 = String::with_capacity(4 * self.len() / 3);

        for block in self.chunks(3) {
            for b64_char in block_to_base64(block) {
                base64.push(b64_char);
            }
        }

        // padding
        if self.len() % 3 >= 1 {
            base64.pop();
            if self.len() % 3 == 1 {
                base64.pop();
                base64.push('=');
            }
            base64.push('=');
        }

        base64
    }
}

/// Converts a block of 3 bytes to an iterator with 4 base64 encoded characters
fn block_to_base64(block: &[u8]) -> Vec<char> {
    let mut b64_chars = Vec::with_capacity(4);

    let (a, b, c) = match block.len() {
        3 => (block[0], block[1], block[2]),
        2 => (block[0], block[1], 0),
        1 => (block[0], 0, 0),
        _ => return vec![],
    };

    // first 6 bits of a
    b64_chars.push(u8_to_base64(a >> 2));

    // last 2 bits of a followed by the first 4 bits of b
    b64_chars.push(u8_to_base64(a % 4 * 16 + (b >> 4)));

    // last 4 bits of b followed by the first 2 bits of c
    b64_chars.push(u8_to_base64(b % 16 * 4 + (c >> 6)));

    // last 6 bits of c
    b64_chars.push(u8_to_base64(c & 0x3f));

    b64_chars
}

/// Converts a u8 representing a base64 sextet to the respective base64 representation
fn u8_to_base64(u: u8) -> char {
    match u {
        0..=25 => (b'A' + u) as char,
        26..=51 => (b'a' + (u - 26)) as char,
        52..=61 => (b'0' + (u - 52)) as char,
        62 => '=',
        63 => '/',
        _ => panic!("byte exceeded range for base64 conversion: {}", u),
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

    #[test]
    fn bytes_to_base64_padding_0() {
        let input = vec![108, 105, 103, 104, 116, 32, 119, 111, 114];
        let result = input.to_base64();
        let expected = String::from("bGlnaHQgd29y");
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_to_base64_padding_1() {
        let input = vec![108, 105, 103, 104, 116, 32, 119, 111, 114, 107, 46];
        let result = input.to_base64();
        let expected = String::from("bGlnaHQgd29yay4=");
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_to_base64_padding_2() {
        let input = vec![108, 105, 103, 104, 116, 32, 119, 111, 114, 107];
        let result = input.to_base64();
        let expected = String::from("bGlnaHQgd29yaw==");
        assert_eq!(result, expected);
    }

    #[test]
    fn bytes_to_base64_empty() {
        let input = vec![];
        let result = input.to_base64();
        let expected = String::from("");
        assert_eq!(result, expected);
    }
}
