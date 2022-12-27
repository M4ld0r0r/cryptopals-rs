use std::fs::File;
use std::io::{prelude::*, BufReader};

use aes::{Aes128, Mode};
use encoding::Decode;

static INPUT_FILE_PATH: &str = "./challenges/set01/challenge07/data/7.txt";
static KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let f = File::open(INPUT_FILE_PATH).unwrap();
    let reader = BufReader::new(f);

    let mut ciphertext = String::new();
    for line in reader.lines() {
        ciphertext.push_str(line.unwrap().trim());
    }

    let ciphertext = Vec::from_base64(&ciphertext).unwrap();

    let cipher = Aes128::new(KEY.as_bytes().to_vec(), Mode::ECB, None).unwrap();

    let plaintext = cipher.decrypt(&ciphertext).unwrap();

    println!(
        "Decrypted text:\n\n{:?}",
        std::str::from_utf8(&plaintext).unwrap()
    );
}
