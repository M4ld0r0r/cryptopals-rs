use encoding::Encode;
use xor::xor;

static PLAINTEXT: &str =
    "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
static KEY: &str = "ICE";
static EXPECTED_CIPHERTEXT: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

fn main() {
    let ciphertext = xor(PLAINTEXT.as_bytes(), KEY.as_bytes()).to_hex();

    println!("\nPlaintext:\n{}\n", PLAINTEXT);
    println!("Key:\n{}\n", KEY);
    println!("Ciphertext (hex):\n{}\n", ciphertext);

    assert_eq!(ciphertext, EXPECTED_CIPHERTEXT);
}
