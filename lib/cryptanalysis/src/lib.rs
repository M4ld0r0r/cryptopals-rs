mod utils;

use utils::*;
use xor::xor;

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
        let mut best_keysize_keys: Vec<Vec<u8>> = Vec::with_capacity(2);
        best_keysize_keys.push(vec![]);
        best_keysize_keys.push(vec![]);

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
}
