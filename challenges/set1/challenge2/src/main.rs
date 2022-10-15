/// Fixed XOR
/// 
/// 
/// Write a function that takes two equal-length buffers and produces their XOR combination.
/// 
/// If your function works properly, then when you feed it the string:
/// 
/// 1c0111001f010100061a024b53535009181c
/// 
/// ... after hex decoding, and when XOR'd against:
/// 
/// 686974207468652062756c6c277320657965
/// 
/// ... should produce:
/// 
/// 746865206b696420646f6e277420706c6179

use encoding::{Encode, Decode};
use xor::xor;

static INPUT_1: &str = "1c0111001f010100061a024b53535009181c";
static INPUT_2: &str = "686974207468652062756c6c277320657965";
static EXPECTED_RESULT: &str = "746865206b696420646f6e277420706c6179";

fn main() { 
    let input_1 = Vec::from_hex(INPUT_1).unwrap();
    let input_2 = Vec::from_hex(INPUT_2).unwrap();

    let result = xor(&input_1, &input_2);
    let hex_result = result.to_hex();

    println!("Input string 1: {}", INPUT_1);
    println!("Input string 2: {}", INPUT_2);
    println!("XOR output: {}", hex_result);

    assert_eq!(hex_result, EXPECTED_RESULT);
}
