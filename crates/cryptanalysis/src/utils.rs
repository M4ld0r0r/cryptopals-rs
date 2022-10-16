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
    // we use BTreeMap instead of a HashMap because we want it be ordered
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

fn is_alphabetic(c: u8) -> bool {
    (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}
