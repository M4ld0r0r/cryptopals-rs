use std::fs::File;
use std::io::{prelude::*, BufReader};

use cryptanalysis::detect_aes_ecb_mode;
use encoding::Decode;

static INPUT_FILE_PATH: &str = "./challenges/set01/challenge08/data/8.txt";

fn main() {
    let f = File::open(INPUT_FILE_PATH).unwrap();
    let reader = BufReader::new(f);

    for (i, line) in reader.lines().enumerate() {
        let ciphertext = Vec::from_hex(line.unwrap().trim()).unwrap();

        let n_repeated_blocks = detect_aes_ecb_mode(&ciphertext);
        if n_repeated_blocks > 0 {
            println!(
                "Line {} contains {} repeated blocks of 16 bytes -> possibly encrypted using AES in ECB mode", 
                i + 1,
                n_repeated_blocks
            );
            return;
        }
    }

    println!("Couldn't detect AES in ECB mode in any of the input lines");
}
