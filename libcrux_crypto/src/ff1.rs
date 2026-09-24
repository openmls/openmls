//! FF1-AES128 small-space pseudorandom permutation backing the
//! virtual-clients-draft `reuse_guard` construction.
//!
//! The mls-virtual-clients draft (Small-Space PRP section) specifies FF1
//! ([NIST SP 800-38G]) with the input-output space of 32-bit integers,
//! instantiated with AES-128. The 32-bit value is mapped to a radix-2
//! numeral string via its big-endian byte encoding, and the tweak is
//! empty.
//!
//! libcrux has no FF1 implementation, so this provider uses the
//! RustCrypto-based `fpe` crate, like `openmls_rust_crypto`.
//!
//! [NIST SP 800-38G]: https://csrc.nist.gov/pubs/sp/800/38/g/final

use aes::Aes128;
use fpe::ff1::{BinaryNumeralString, FF1};
use openmls_traits::types::CryptoError;

const RADIX: u32 = 2;

/// FF1-AES128 encryption of a 32-bit value under a 16-byte PRP key.
///
/// Inverse of [`decrypt`].
pub(crate) fn encrypt(key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
    let ff1 = FF1::<Aes128>::new(key, RADIX).map_err(|_| CryptoError::CryptoLibraryError)?;
    let input = BinaryNumeralString::from_bytes_le(&plaintext.to_be_bytes());
    let output = ff1
        .encrypt(&[], &input)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    numeral_string_to_u32(output)
}

/// Inverse of [`encrypt`]: recover the 32-bit pre-image of a permuted value.
pub(crate) fn decrypt(key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
    let ff1 = FF1::<Aes128>::new(key, RADIX).map_err(|_| CryptoError::CryptoLibraryError)?;
    let input = BinaryNumeralString::from_bytes_le(&ciphertext.to_be_bytes());
    let output = ff1
        .decrypt(&[], &input)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    numeral_string_to_u32(output)
}

fn numeral_string_to_u32(numeral_string: BinaryNumeralString) -> Result<u32, CryptoError> {
    let bytes: [u8; 4] = numeral_string
        .to_bytes_le()
        .try_into()
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed test vector pinning the radix, byte ordering, and FF1
    /// output. The same vector is pinned in `openmls_rust_crypto` so the
    /// providers stay in agreement.
    #[test]
    fn fixed_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let x: u32 = 0x0123_4567;
        let permuted = encrypt(&key, x).expect("encrypt");
        assert_eq!(decrypt(&key, permuted).expect("decrypt"), x);
        assert_eq!(permuted, 0xa1ba_5e30, "got {permuted:#010x}");
    }
}
