//! Here we choose one of the crypto backends. This is either Evercrypt or RustCrypto

#[cfg(all(feature = "evercrypt-backend", not(feature = "rust-crypto")))]
mod evercrypt_provider;
#[cfg(all(feature = "evercrypt-backend", not(feature = "rust-crypto")))]
pub(crate) use evercrypt_provider::*;
#[cfg(all(feature = "rust-crypto", not(feature = "evercrypt-backend")))]
mod rust_crypto_provider;
#[cfg(all(feature = "rust-crypto", not(feature = "evercrypt-backend")))]
pub(crate) use rust_crypto_provider::*;

#[cfg(test)]
pub(crate) fn aead_key_gen(alg: crypto_algorithms::AeadType) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    match alg {
        crypto_algorithms::AeadType::Aes128Gcm => {
            let mut k = [0u8; 16];
            OsRng.fill_bytes(&mut k);
            k.into()
        }
        crypto_algorithms::AeadType::Aes256Gcm | crypto_algorithms::AeadType::ChaCha20Poly1305 => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k.into()
        }
        crypto_algorithms::AeadType::HpkeExport => vec![],
    }
}
