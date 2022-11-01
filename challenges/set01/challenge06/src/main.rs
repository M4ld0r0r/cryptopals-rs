use std::fs::File;
use std::io::{prelude::*, BufReader};

use cryptanalysis::break_repeating_key_xor;
use encoding::Decode;

static INPUT_FILE_PATH: &str = "./challenges/set01/challenge06/data/6.txt";

fn main() {

    let f = File::open(INPUT_FILE_PATH).unwrap();
    let reader = BufReader::new(f);

    let mut ciphertext = String::new();
    for line in reader.lines() {
        ciphertext.push_str(line.unwrap().trim());
    }

    let ciphertext = Vec::from_base64(&ciphertext).unwrap();
    let best_keys = break_repeating_key_xor(&ciphertext, 2, 40, "EN");

    println!("Best key candidates:\n");
    for key in best_keys {
        println!("{:?}", String::from_utf8(key).unwrap());
    }
}
