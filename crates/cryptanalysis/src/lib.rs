mod utils;
use utils::*;

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
