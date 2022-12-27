use std::collections::HashSet;

mod utils;

use primitives::xor;
use utils::*;

/// Attack the repeating key XOR cipher using the Kasiski Examination method.
///
/// # Args
/// `text`: The target ciphertext
///
/// `min_keysize`: The minimum keysize to test
///
/// `max_keysize`: The maximum keysize to text
///
/// `lang`: The suspected source language (e.g. "EN")
///
/// # Returns
/// A `Vec<Vec<u8>>` with the 6 highest scoring keys in descending order
pub fn break_repeating_key_xor(
    text: &[u8],
    min_keysize: usize,
    max_keysize: usize,
    lang: &str,
) -> Vec<Vec<u8>> {
    let keysize_scores = rate_keysizes(text, min_keysize, max_keysize);
    let mut best_keys: Vec<Vec<u8>> = Vec::with_capacity(6);

    // we are interested in the best 2 keys for the best 3 keysizes
    keysize_scores.iter().take(3).for_each(|(keysize, _)| {
        let mut best_keysize_keys: Vec<Vec<u8>> = vec![vec![], vec![]];

        let blocks = transpose_blocks(text, *keysize);

        // get the 2 best single-byte keys for each transposed block
        // each single-byte key is a part of the multi-byte key
        for block in blocks {
            let key_scores = break_single_byte_xor(&block, lang);

            best_keysize_keys[0].push(key_scores[0].0);
            best_keysize_keys[1].push(key_scores[1].0);
        }
        best_keys.push(best_keysize_keys[0].clone());
        best_keys.push(best_keysize_keys[1].clone());
    });

    best_keys
}

/// Attack the single byte XOR cipher by tryng all 256 possible keys
/// and attributing a score to each of them.
/// Each score represents how likely it is for the resulting plaintext (decrypted using that key)
/// to be written in the source language.
///
/// # Args
/// `text`: The target ciphertext
///
/// `lang`: The suspected source language (e.g. "EN")
///
/// # Returns
/// A `Vec<(u8, usize)>` containing the scores for all the possible keys in descending order
pub fn break_single_byte_xor(text: &[u8], lang: &str) -> Vec<(u8, usize)> {
    let mut key_scores: Vec<(u8, usize)> = Vec::with_capacity(256);

    for key in 0x00..=0xFF {
        let xor_result = xor(text, &[key]);
        let key_score = calculate_lang_score(&xor_result, lang);
        key_scores.push((key, key_score));
    }

    key_scores.sort_by(|a, b| b.1.cmp(&a.1));

    key_scores
}

/// Calculate how likely it is for the given text to be written in the given language
///
/// # Args
/// `text`: The text we want to analyze
///
/// `lang`: The source language abbrevation (ex: English -> "EN")
///
/// # Returns
/// A `usize` value between 0 and 12, 0 meaning that the text is definitely not written in
/// the language and 12 meaning that the language is definitely written in the source language
pub fn calculate_lang_score(text: &[u8], lang: &str) -> usize {
    let source_lang_freqs = get_source_lang_freqs(lang).as_bytes();
    let mut score = 0;

    let letter_counts = get_letter_counts(text);

    // sort letter counts from highest to lowest
    let mut c: Vec<_> = letter_counts.iter().collect();
    c.sort_by(|a, b| b.1.cmp(a.1));

    // check if the 6 most and least frequent chars match those of the source language
    for (u, _) in &c[0..6] {
        if source_lang_freqs[0..6].contains(*u) {
            score += 1;
        }
    }
    for (u, _) in &c[19..26] {
        if source_lang_freqs[19..26].contains(*u) {
            score += 1;
        }
    }

    score
}

/// Test if a given ciphertext is likely to be encrypted using AES in ECB mode by checking
/// if there are repeated blocks of 16 bytes
///
/// # Args
/// `ciphertext`: The ciphertext we want to test
///
/// # Returns
/// A `usize` value with the number of repeated blocks
pub fn detect_aes_ecb_mode(ciphertext: &[u8]) -> usize {
    let chunks = ciphertext.chunks(AES_BLOCKSIZE);
    let unique_chunks: HashSet<&[u8]> = HashSet::from_iter(chunks.clone());

    // If there are repeated blocks, the difference between the total number of chunks
    // and the number of unique chunks is greater than 0
    chunks.len() - unique_chunks.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_xor_attack() {
        let text = [
            27, 55, 55, 51, 49, 54, 63, 120, 21, 27, 127, 43, 120, 52, 49, 51, 61, 120, 57, 120,
            40, 55, 45, 54, 60, 120, 55, 62, 120, 58, 57, 59, 55, 54,
        ];
        let key_scores = break_single_byte_xor(&text, "EN");
        let expected = 0x58;
        assert_eq!(key_scores[0].0, expected);
    }

    #[test]
    fn aes_in_ecb_mode_detection() {
        let ciphertext = [
            216, 128, 97, 151, 64, 168, 161, 155, 120, 64, 168, 163, 28, 129, 10, 61, 8, 100, 154,
            247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 226, 221, 5, 47, 107,
            100, 29, 191, 157, 17, 176, 52, 133, 66, 187, 87, 8, 100, 154, 247, 13, 192, 111, 79,
            213, 210, 214, 156, 116, 76, 210, 131, 148, 117, 201, 223, 219, 193, 212, 101, 151,
            148, 157, 156, 126, 130, 191, 90, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214,
            156, 116, 76, 210, 131, 151, 169, 62, 171, 141, 106, 236, 213, 102, 72, 145, 84, 120,
            154, 107, 3, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131,
            212, 3, 24, 12, 152, 200, 246, 219, 31, 42, 63, 156, 64, 64, 222, 176, 171, 81, 178,
            153, 51, 242, 193, 35, 197, 131, 134, 176, 111, 186, 24, 106,
        ];
        let result = detect_aes_ecb_mode(&ciphertext);
        let expected = 3;
        assert_eq!(result, expected);
    }
}
