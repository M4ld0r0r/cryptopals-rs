use primitives::pad_pkcs7;

static BLOCK_SIZE: usize = 20;

static TEXT: &str = "YELLOW SUBMARINE";
static EXPECTED: &str = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}";

fn main() {
    let result = pad_pkcs7(TEXT.as_bytes(), BLOCK_SIZE).unwrap();
    let result = std::str::from_utf8(&result).unwrap();

    println!("Input text: {}", TEXT);
    println!("Padded to 20 bytes block size: {:?}", result);

    assert_eq!(result, EXPECTED);
}
