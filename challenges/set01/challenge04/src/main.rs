use std::fs::File;
use std::io::{prelude::*, BufReader};

use cryptanalysis::break_single_byte_xor;
use encoding::{Decode, Encode};
use primitives::xor;

static INPUT_FILE_PATH: &str = "./challenges/set01/challenge04/data/4.txt";

fn main() {
    let f = File::open(INPUT_FILE_PATH).unwrap();
    let reader = BufReader::new(f);

    let mut best_score = 0;
    let mut best_line = Vec::new();
    let mut best_key = 0x00;

    for line in reader.lines() {
        let bytes = Vec::from_hex(&line.unwrap()).unwrap();

        let key_scores = break_single_byte_xor(&bytes, "EN");
        let (key, score) = key_scores[0];

        if score > best_score {
            best_key = key;
            best_score = score;
            best_line = bytes.clone();
        }
    }

    let plaintext_bytes = xor(&best_line, &[best_key]);
    let plaintext = std::str::from_utf8(&plaintext_bytes).unwrap();

    println!("Original line: {}", best_line.to_hex());
    println!("Key: 0x{:x}", best_key);
    println!("Plaintext: {}", plaintext);
    println!("Score: {}/12", best_score);
}
