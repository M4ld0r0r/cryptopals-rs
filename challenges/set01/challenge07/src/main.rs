use std::fs::File;
use std::io::{prelude::*, BufReader};

use openssl::cipher;
use openssl::symm::{Cipher, Crypter, Mode};

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

    let mut plaintext = vec![0x0; ciphertext.len()];

    // decrypt
    let decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, KEY.as_bytes(), None);
    decrypter
        .unwrap()
        .update(&ciphertext, &mut plaintext)
        .unwrap();

    println!(
        "Decrypted text:\n\n{:?}",
        std::str::from_utf8(&plaintext).unwrap()
    );
}
