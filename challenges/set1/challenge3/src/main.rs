// Single-byte XOR cipher
//
// The hex encoded string:
//
// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
//
// ... has been XOR'd against a single character. Find the key, decrypt the message.
//
// You can do this by hand. But don't: write code to do it for you.
//
// How? Devise some method for "scoring" a piece of English plaintext.
// Character frequency is a good metric. Evaluate each output and choose the one with the best score.

use std::str;

use cryptanalysis::calculate_lang_score;
use encoding::Decode;
use xor::xor;

static CIPHERTEXT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
    let ciphertext_bytes = Vec::from_hex(CIPHERTEXT).unwrap();

    let mut best_key = 0x00;
    let mut best_key_score = 0;

    // brute force attack + frequency analysis
    for key in 0x00..=0xFF {
        let xor_result = xor(&ciphertext_bytes, &[key]);
        let key_score = calculate_lang_score(&xor_result, "EN");

        if key_score > best_key_score {
            best_key = key;
            best_key_score = key_score;
        }
    }

    let plaintext_bytes = xor(&ciphertext_bytes, &[best_key]);
    let plaintext = str::from_utf8(&plaintext_bytes).unwrap();

    println!("Key: {}", best_key);
    println!("Plaintext: {}", plaintext);
    println!("Score: {}/12", best_key_score);
}
