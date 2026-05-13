//! Small-space pseudorandom permutation used by the virtual-clients-draft
//! `reuse_guard` construction.
//!
//! The mls-virtual-clients draft (Small-Space PRP section) specifies FF1
//! ([NIST SP 800-38G]) with the input-output space of 32-bit integers,
//! instantiated with AES-128.
//!
//! [NIST SP 800-38G]: https://csrc.nist.gov/pubs/sp/800/38/g/final

use aes::Aes128;
use fpe::ff1::{BinaryNumeralString, FF1};
use openmls_traits::types::CryptoError;

const RADIX: u32 = 2;

/// FF1-AES128 encryption of a 32-bit value under a 16-byte PRP key.
///
/// Returns the 4-byte big-endian encoding of the permuted value. Inverse of
/// [`decrypt`].
pub(crate) fn encrypt(prp_key: &[u8; 16], x: u32) -> Result<[u8; 4], CryptoError> {
    let ff1 = FF1::<Aes128>::new(prp_key, RADIX).map_err(|e| {
        log::error!("small_space_prp: FF1 instantiation failed: {e:?}");
        CryptoError::CryptoLibraryError
    })?;
    let input = BinaryNumeralString::from_bytes_le(&x.to_be_bytes());
    let output = ff1.encrypt(&[], &input).map_err(|e| {
        log::error!("small_space_prp: FF1 encrypt failed: {e:?}");
        CryptoError::CryptoLibraryError
    })?;
    let bytes: Vec<u8> = output.to_bytes_le();
    bytes.try_into().map_err(|got: Vec<u8>| {
        log::error!(
            "small_space_prp: FF1 encrypt output had unexpected length {} (expected 4)",
            got.len()
        );
        CryptoError::CryptoLibraryError
    })
}

/// Inverse of [`encrypt`]: recover the 32-bit pre-image of a 4-byte guard.
pub(crate) fn decrypt(prp_key: &[u8; 16], guard: [u8; 4]) -> Result<u32, CryptoError> {
    let ff1 = FF1::<Aes128>::new(prp_key, RADIX).map_err(|e| {
        log::error!("small_space_prp: FF1 instantiation failed: {e:?}");
        CryptoError::CryptoLibraryError
    })?;
    let input = BinaryNumeralString::from_bytes_le(&guard);
    let output = ff1.decrypt(&[], &input).map_err(|e| {
        log::error!("small_space_prp: FF1 decrypt failed: {e:?}");
        CryptoError::CryptoLibraryError
    })?;
    let bytes: [u8; 4] = output.to_bytes_le().try_into().map_err(|got: Vec<u8>| {
        log::error!(
            "small_space_prp: FF1 decrypt output had unexpected length {} (expected 4)",
            got.len()
        );
        CryptoError::CryptoLibraryError
    })?;
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `decrypt(encrypt(x)) == x` for a spread of values across the 32-bit
    /// domain (extremes, mid-range, a few "boring" values). Catches breakage
    /// of either direction independently.
    #[test]
    fn roundtrip() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        for &x in &[
            0u32,
            1,
            0xff,
            0x100,
            0xdead_beef,
            0x8000_0000,
            u32::MAX - 1,
            u32::MAX,
        ] {
            let guard = encrypt(&key, x).expect("encrypt");
            let back = decrypt(&key, guard).expect("decrypt");
            assert_eq!(back, x, "round-trip failed for {x:#010x}");
        }
    }

    /// Determinism: same key, same input → same output. (FF1 has no
    /// randomness, but if a future refactor pulls in a randomized variant
    /// we want the build to fail loudly.)
    #[test]
    fn deterministic() {
        let key = [0xa5u8; 16];
        let a = encrypt(&key, 0x1234_5678).expect("encrypt a");
        let b = encrypt(&key, 0x1234_5678).expect("encrypt b");
        assert_eq!(a, b);
    }

    /// Fixed test vector pinning the radix, byte ordering, and FF1
    /// output. Catches conventions drift before it shows up as a silent
    /// decrypt mismatch between two openmls clients.
    #[test]
    fn fixed_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let x: u32 = 0x0123_4567;
        let guard = encrypt(&key, x).expect("encrypt");
        // Round-trip is the load-bearing check. The absolute output bytes
        // are pinned below.
        assert_eq!(decrypt(&key, guard).expect("decrypt"), x);
        // Locked output for the inputs above. Update intentionally if the
        // wrapper ever changes its conventions.
        let expected: [u8; 4] = [0xa1, 0xba, 0x5e, 0x30];
        assert_eq!(guard, expected, "got {guard:02x?}");
    }
}
