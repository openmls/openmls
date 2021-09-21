//! Here we choose one of the crypto backends. This is either Evercrypt or RustCrypto
//! Evercrypt is the default. But if rust-crypto is enabled, it is used.

use crypto_algorithms::{AeadType, HashType};
use paste::paste;

use super::{CryptoError, SignatureScheme};

#[cfg(not(feature = "rust-crypto"))]
mod evercrypt_provider;
#[cfg(not(feature = "rust-crypto"))]
use evercrypt_provider::*;
#[cfg(feature = "rust-crypto")]
mod rust_crypto_provider;
#[cfg(feature = "rust-crypto")]
use rust_crypto_provider::*;
#[cfg(not(feature = "rust-crypto"))]
mod rust_crypto_stub;
#[cfg(not(feature = "rust-crypto"))]
use rust_crypto_stub::*;

macro_rules! call {
    ( pub(crate) fn $fn:ident ( $($name:ident : $type:ty),* ) -> $ret:ty ) => {
        pub(crate) fn $fn (
            $(
                $name: $type
            ),*
        ) -> $ret {
            paste! {
                if cfg!(feature = "rust-crypto") {
                    // RC is the only other option
                    [<rc_ $fn>](
                        $(
                            $name
                        ),*
                    )
                } else {
                    // By default we use evercrypt
                    [<ec_ $fn>](
                        $(
                            $name
                        ),*
                    )
                }
            }
        }
    }
}

call! {
    pub(crate) fn support(signature_scheme: SignatureScheme) -> Result<(), CryptoError>
}

call! {
    pub(crate) fn hkdf_extract(hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, CryptoError>
}

call! {
    pub(crate) fn hkdf_expand(hash_type: HashType, prk: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>, CryptoError>
}

call! {
    pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError>
}
call! {
    pub(crate) fn aead_encrypt(alg: AeadType, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>
}

call! {
    pub(crate) fn aead_decrypt(alg: AeadType, key: &[u8], ct_tag: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>
}

call! {
    pub(crate) fn signature_key_gen(alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError>
}

call! {
    pub(crate) fn verify_signature(alg: SignatureScheme, data: &[u8], pk: &[u8], signature: &[u8]) -> Result<(), CryptoError>
}

call! {
    pub(crate) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>
}

#[cfg(test)]
pub(crate) fn aead_key_gen(alg: AeadType) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};

    match alg {
        AeadType::Aes128Gcm => {
            let mut k = [0u8; 16];
            OsRng.fill_bytes(&mut k);
            k.into()
        }
        AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k.into()
        }
        AeadType::HpkeExport => vec![],
    }
}
