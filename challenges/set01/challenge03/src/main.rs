use std::str;

use cryptanalysis::break_single_byte_xor;
use encoding::Decode;
use primitives::xor;

static CIPHERTEXT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
    let ciphertext_bytes = Vec::from_hex(CIPHERTEXT).unwrap();

    let key_scores = break_single_byte_xor(&ciphertext_bytes, "EN");
    let (best_key, best_key_score) = key_scores[0];

    let plaintext_bytes = xor(&ciphertext_bytes, &[best_key]);
    let plaintext = str::from_utf8(&plaintext_bytes).unwrap();

    println!("Key: 0x{:x}", best_key);
    println!("Plaintext: {}", plaintext);
    println!("Score: {}/12", best_key_score);
}
