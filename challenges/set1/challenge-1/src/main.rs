use encoding::{Encode, Decode};

static HEX_INPUT: &'static str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
static EXPECTED_B64_OUTPUT: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

fn main() {
    let decoded_input = Vec::from_hex(HEX_INPUT).unwrap();
    let b64_out = decoded_input.to_base64();
    
    println!("Hexadecimal input: {}", HEX_INPUT);
    println!("Base64 output: {}", b64_out);

    assert_eq!(b64_out, EXPECTED_B64_OUTPUT);
}
