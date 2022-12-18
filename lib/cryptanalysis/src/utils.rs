use std::collections::BTreeMap;

/// English letter frequencies (highest to lowest)
pub static EN_CHAR_FREQS: &str = "etaoinsrhldcumfpgwybvkxjqz";

pub static AES_BLOCKSIZE: usize = 16;

pub fn get_source_lang_freqs(lang: &str) -> &str {
    match lang {
        "EN" => return EN_CHAR_FREQS,
        _ => unimplemented!("{}", lang),
    };
}

/// Get the frequency count of all the alphabetic chars on the given text
pub fn get_letter_counts(text: &[u8]) -> BTreeMap<u8, i32> {
    // we use BTreeMap instead of a HashMap because we want it to be ordered
    let mut char_count: BTreeMap<u8, i32> = BTreeMap::new();
    for c in 0x61..=0x7A {
        char_count.insert(c, 0);
    }

    for &u in text {
        if is_alphabetic(u) {
            *char_count.get_mut(&u.to_ascii_lowercase()).unwrap() += 1;
        }
    }

    char_count
}

/// Calculates the hamming distance between 2 equal length &[u8]s
pub fn calculate_hamming_distance(s1: &[u8], s2: &[u8]) -> Result<u32, String> {
    if s1.len() != s2.len() {
        return Err("s1 and s2 mut be of equal length".to_string());
    }

    let mut hamming_dist = 0;
    s1.iter().zip(s2).for_each(|(b1, b2)| {
        hamming_dist += (b1 ^ b2).count_ones();
    });

    Ok(hamming_dist)
}

/// Splits the given text in transposed blocks of keysize size
pub fn transpose_blocks(text: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = (0..keysize).map(|_| Vec::new()).collect();
    text.chunks(keysize).for_each(|chunk| {
        chunk.iter().zip(blocks.iter_mut()).for_each(|(&u, block)| {
            block.push(u);
        });
    });
    blocks
}

/// Return a vector with the keysize scores (using hamming distance) in descending order
pub fn rate_keysizes(text: &[u8], min_keysize: usize, max_keysize: usize) -> Vec<(usize, f64)> {
    let mut keysize_hamming_dists: Vec<(usize, f64)> = vec![];

    for keysize in min_keysize..=max_keysize {
        // get the normalized hamming distances between the pairs
        // of the first 4 keysize chunks for each keysize
        let chunks: Vec<&[u8]> = text.chunks(keysize).take(4).collect();
        let mut hamming_dist = 0;
        for i in 0..4 {
            for j in i..4 {
                hamming_dist += calculate_hamming_distance(chunks[i], chunks[j]).unwrap();
            }
        }
        keysize_hamming_dists.push((keysize, (hamming_dist / keysize as u32).into()));
    }
    keysize_hamming_dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    keysize_hamming_dists
}

fn is_alphabetic(c: u8) -> bool {
    (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance() {
        let s1 = "wokka wokka!!!".as_bytes();
        let s2 = "this is a test".as_bytes();
        let result = calculate_hamming_distance(s1, s2).unwrap();
        let expected = 37;
        assert_eq!(result, expected);
    }

    #[test]
    fn transpose_blocks_divisible_length() {
        let text = vec![0x00, 0x23, 0x34, 0x58, 0xF3, 0xFF, 0xAB, 0xEE];
        let keysize = 4;
        let result = transpose_blocks(&text, keysize);
        let expected = vec![
            vec![0x00, 0xF3],
            vec![0x23, 0xFF],
            vec![0x34, 0xAB],
            vec![0x58, 0xEE],
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn transpose_blocks_not_divisible_length() {
        let text = vec![0x00, 0x23, 0x34, 0x58, 0xF3, 0xFF, 0xAB, 0xEE, 0x44];
        let keysize = 4;
        let result = transpose_blocks(&text, keysize);
        let expected = vec![
            vec![0x00, 0xF3, 0x44],
            vec![0x23, 0xFF],
            vec![0x34, 0xAB],
            vec![0x58, 0xEE],
        ];
        assert_eq!(result, expected);
    }
}
