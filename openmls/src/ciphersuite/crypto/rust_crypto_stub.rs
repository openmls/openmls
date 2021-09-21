use crypto_algorithms::{AeadType, HashType};

use crate::ciphersuite::{CryptoError, SignatureScheme};

pub(crate) fn rc_support(_signature_scheme: SignatureScheme) -> Result<(), CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_hkdf_extract(
    _hash_type: HashType,
    _salt: &[u8],
    _ikm: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_hkdf_expand(
    _hash_type: HashType,
    _prk: &[u8],
    _info: &[u8],
    _okm_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_hash(_hash_type: HashType, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_aead_encrypt(
    _alg: AeadType,
    _key: &[u8],
    _data: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_aead_decrypt(
    _alg: AeadType,
    _key: &[u8],
    _ct_tag: &[u8],
    _nonce: &[u8],
    _aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}

/// Returns `(sk, pk)`
pub(crate) fn rc_signature_key_gen(
    _alg: SignatureScheme,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_verify_signature(
    _alg: SignatureScheme,
    _data: &[u8],
    _pk: &[u8],
    _signature: &[u8],
) -> Result<(), CryptoError> {
    unimplemented!()
}

pub(crate) fn rc_sign(
    _alg: SignatureScheme,
    _data: &[u8],
    _key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    unimplemented!()
}
