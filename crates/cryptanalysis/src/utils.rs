use std::collections::BTreeMap;

/// English letter frequencies (highest to lowest)
pub static EN_CHAR_FREQS: &str = "etaoinsrhldcumfpgwybvkxjqz";

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

// Calculates the hamming distance between 2 equal length &[u8]s
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
}
