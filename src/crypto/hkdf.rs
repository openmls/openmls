// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crypto::hmac::*;

#[derive(Debug)]
pub enum HKDFError {
    InvalidLength,
}

pub fn hkdf(
    algorithm: HMACAlgorithm,
    salt: &[u8],
    input: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, HKDFError> {
    expand(algorithm, &extract(algorithm, salt, input), info, length)
}

pub fn extract(algorithm: HMACAlgorithm, salt: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mac = HMAC::new(algorithm, salt).unwrap();
    mac.input(input);
    mac.result()
}

pub fn expand(
    algorithm: HMACAlgorithm,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, HKDFError> {
    let hash_len = hash_length(algorithm);
    if length > (255 * hash_len) {
        return Err(HKDFError::InvalidLength);
    }
    let n = (length as f32 / hash_len as f32).ceil() as usize;
    let mut t_n = vec![];
    let mut okm = vec![];

    for i in 1..=n {
        let mut concat = Vec::with_capacity(t_n.len() + info.len() + 1);
        concat.extend(&t_n);
        concat.extend(info);
        concat.push(i as u8);
        let code = extract(algorithm, prk, &concat);
        okm.extend(&code);
        t_n = code;
    }
    Ok(okm.into_iter().take(length).collect())
}

#[test]
fn test_case_1() {
    use utils::*;

    let algorithm = HMACAlgorithm::SHA256;

    let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_to_bytes("000102030405060708090a0b0c");
    let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
    let len = 42;

    let expected_prk =
        hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let expected_okm = hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    let prk = extract(algorithm, &salt, &ikm);
    let okm = expand(algorithm, &prk, &info, len).unwrap();

    assert_eq!(&expected_prk, &prk);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_2() {
    use utils::*;

    let algorithm = HMACAlgorithm::SHA256;

    let ikm  = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    let salt = hex_to_bytes("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    let info = hex_to_bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let len = 82;

    let expected_prk =
        hex_to_bytes("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
    let expected_okm = hex_to_bytes("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

    let prk = extract(algorithm, &salt, &ikm);
    let okm = expand(algorithm, &prk, &info, len).unwrap();

    assert_eq!(&expected_prk, &prk);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_3() {
    use utils::*;

    let algorithm = HMACAlgorithm::SHA256;

    let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = vec![];
    let info = vec![];
    let len = 42;

    let expected_prk =
        hex_to_bytes("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    let expected_okm = hex_to_bytes(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );

    let prk = extract(algorithm, &salt, &ikm);
    let okm = expand(algorithm, &prk, &info, len).unwrap();

    assert_eq!(&expected_prk, &prk);
    assert_eq!(&expected_okm, &okm);
}
