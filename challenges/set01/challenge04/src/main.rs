// Detect single-character XOR
//
//
// One of the 60-character strings in this file has been encrypted by single-character XOR.
//
// Find it.
//
// (Your code from #3 should help.)

use std::fs::File;
use std::io::{prelude::*, BufReader};

use cryptanalysis::calculate_lang_score;
use encoding::{Decode, Encode};
use xor::xor;

static INPUT_FILE_PATH: &str = "./challenges/set01/challenge04/data/4.txt";

fn main() {
    let f = File::open(INPUT_FILE_PATH).unwrap();
    let reader = BufReader::new(f);

    let mut best_score = 0;
    let mut best_line = Vec::new();
    let mut best_key = 0x00;

    for line in reader.lines() {
        let bytes = Vec::from_hex(&line.unwrap()).unwrap();

        for key in 0x00..=0xFF {
            let xor_result = xor(&bytes, &[key]);
            let key_score = calculate_lang_score(&xor_result, "EN");

            if key_score > best_score {
                best_key = key;
                best_score = key_score;
                best_line = bytes.clone();
            }
        }
    }

    let plaintext_bytes = xor(&best_line, &[best_key]);
    let plaintext = std::str::from_utf8(&plaintext_bytes).unwrap();

    println!("Original line: {}", best_line.to_hex());
    println!("Key: 0x{:x}", best_key);
    println!("Plaintext: {}", plaintext);
    println!("Score: {}/12", best_score);
}
