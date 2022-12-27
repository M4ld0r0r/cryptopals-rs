# cryptopals-rs
Solutions to the [Cryptopals crypto challenges](https://cryptopals.com/) written in Rust

## Usage

```
cd cryptopals-rs
cargo run --bin challengeX # where X ∈ {01, 02, 03, ..., 66}
```

## Progress 

- [x] Set 1 
    - [x] [challenge01: Convert hex to base64](https://cryptopals.com/sets/1/challenges/1)
    - [x] [challenge02: Fixed XOR](https://cryptopals.com/sets/1/challenges/2)
    - [x] [challenge03: Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)
    - [x] [challenge04: Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)
    - [x] [challenge05: Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)
    - [x] [challenge06: Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6)
    - [x] [challenge07: AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)
    - [x] [challenge08: Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)
- [ ] Set 2
    - [x] [challenge09: Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9)
    - [x] [challenge10: Implement CBC mode](https://cryptopals.com/sets/2/challenges/10)
    - [ ] [challenge11: An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11)
    - [ ] [challenge12: Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12)
    - [ ] [challenge13: ECB cut-and-paste](https://cryptopals.com/sets/2/challenges/13)
    - [ ] [challenge14: Byte-at-a-time ECB decryption (Harder)](https://cryptopals.com/sets/2/challenges/14)
    - [ ] [challenge15: PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)
    - [ ] [challenge16: CBC bitflipping attacks](https://cryptopals.com/sets/2/challenges/16)
- [ ] Set 3
    - [ ] [challenge17: The CBC padding oracle](https://cryptopals.com/sets/3/challenges/17)
    - [ ] [challenge18: Implement CTR, the stream cipher mode](https://cryptopals.com/sets/3/challenges/18)
    - [ ] [challenge19: Break fixed-nonce CTR mode using substitutions](https://cryptopals.com/sets/3/challenges/19)
    - [ ] [challenge20: Break fixed-nonce CTR statistically](https://cryptopals.com/sets/3/challenges/20)
    - [ ] [challenge21: Implement the MT19937 Mersenne Twister RNG](https://cryptopals.com/sets/3/challenges/21)
    - [ ] [challenge22: Crack an MT19937 seed](https://cryptopals.com/sets/3/challenges/22)
    - [ ] [challenge23: Clone an MT19937 RNG from its output](https://cryptopals.com/sets/3/challenges/23)
    - [ ] [challenge24: Create the MT19937 stream cipher and break it](https://cryptopals.com/sets/3/challenges/24)
- [ ] Set 4
    - [ ] [challenge25: Break "random access read/write" AES CTR](https://cryptopals.com/sets/4/challenges/25)
    - [ ] [challenge26: CTR bitflipping](https://cryptopals.com/sets/4/challenges/26)
    - [ ] [challenge27: Recover the key from CBC with IV=Key](https://cryptopals.com/sets/4/challenges/27)
    - [ ] [challenge28: Implement a SHA-1 keyed MAC](https://cryptopals.com/sets/4/challenges/28)
    - [ ] [challenge29: Break a SHA-1 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/29)
    - [ ] [challenge30: Break an MD4 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/30)
    - [ ] [challenge31: Implement and break HMAC-SHA1 with an artificial timing leak](https://cryptopals.com/sets/4/challenges/31)
    - [ ] [challenge32: Break HMAC-SHA1 with a slightly less artificial timing leak](https://cryptopals.com/sets/4/challenges/32)
- [ ] Set 5
    - [ ] [challenge33: Implement Diffie-Hellman](https://cryptopals.com/sets/5/challenges/33)
    - [ ] [challenge34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](https://cryptopals.com/sets/5/challenges/34)
    - [ ] [challenge35: Implement DH with negotiated groups, and break with malicious "g" parameters](https://cryptopals.com/sets/5/challenges/35)
    - [ ] [challenge36: Implement Secure Remote Password (SRP)](https://cryptopals.com/sets/5/challenges/36)
    - [ ] [challenge37: Break SRP with a zero key](https://cryptopals.com/sets/5/challenges/37)
    - [ ] [challenge38: Offline dictionary attack on simplified SRP](https://cryptopals.com/sets/5/challenges/38)
    - [ ] [challenge39: Implement RSA](https://cryptopals.com/sets/5/challenges/39)
    - [ ] [challenge40: Implement an E=3 RSA Broadcast attack](https://cryptopals.com/sets/5/challenges/40)
- [ ] Set 6
    - [ ] [challenge41: Implement unpadded message recovery oracle](https://cryptopals.com/sets/6/challenges/41)
    - [ ] [challenge42: Bleichenbacher's e=3 RSA Attack](https://cryptopals.com/sets/6/challenges/42)
    - [ ] [challenge43: DSA key recovery from nonce](https://cryptopals.com/sets/6/challenges/43)
    - [ ] [challenge44: DSA nonce recovery from repeated nonce](https://cryptopals.com/sets/6/challenges/44)
    - [ ] [challenge45: DSA parameter tampering](https://cryptopals.com/sets/6/challenges/45)
    - [ ] [challenge46: RSA parity oracle](https://cryptopals.com/sets/6/challenges/46)
    - [ ] [challenge47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](https://cryptopals.com/sets/6/challenges/47)
    - [ ] [challenge48: Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](https://cryptopals.com/sets/6/challenges/48)
- [ ] Set 7
    - [ ] [challenge49: CBC-MAC Message Forgery](https://cryptopals.com/sets/7/challenges/49)
    - [ ] [challenge50: Hashing with CBC-MAC](https://cryptopals.com/sets/7/challenges/50)
    - [ ] [challenge51: Compression Ratio Side-Channel Attacks](https://cryptopals.com/sets/7/challenges/51)
    - [ ] [challenge52: Iterated Hash Function Multicollisions](https://cryptopals.com/sets/7/challenges/52)
    - [ ] [challenge53: Kelsey and Schneier's Expandable Messages](https://cryptopals.com/sets/7/challenges/53)
    - [ ] [challenge54: Kelsey and Kohno's Nostradamus Attack](https://cryptopals.com/sets/7/challenges/54)
    - [ ] [challenge55: MD4 Collisions](https://cryptopals.com/sets/7/challenges/55)
    - [ ] [challenge56: RC4 Single-Byte Biases](https://cryptopals.com/sets/7/challenges/56)
- [ ] Set 8
    - [ ] [challenge57: Diffie-Hellman Revisited: Small Subgroup Confinement](https://cryptopals.com/sets/8/challenges/57.txt)
    - [ ] [challenge58: Pollard's Method for Catching Kangaroos](https://cryptopals.com/sets/8/challenges/58.txt)
    - [ ] [challenge59: Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks](https://cryptopals.com/sets/8/challenges/59.txt)
    - [ ] [challenge60: Single-Coordinate Ladders and Insecure Twists](https://cryptopals.com/sets/8/challenges/60.txt)
    - [ ] [challenge61: Duplicate-Signature Key Selection in ECDSA (and RSA)](https://cryptopals.com/sets/8/challenges/61.txt)
    - [ ] [challenge62: Key-Recovery Attacks on ECDSA with Biased Nonces](https://cryptopals.com/sets/8/challenges/62.txt)
    - [ ] [challenge63: Key-Recovery Attacks on GCM with Repeated Nonces](https://cryptopals.com/sets/8/challenges/63.txt)
    - [ ] [challenge64: Key-Recovery Attacks on GCM with a Truncated MAC](https://cryptopals.com/sets/8/challenges/64.txt)
    - [ ] [challenge65: Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension](https://cryptopals.com/sets/8/challenges/65.txt)
    - [ ] [challenge66: Exploiting Implementation Errors in Diffie-Hellman](https://cryptopals.com/sets/8/challenges/66.txt)