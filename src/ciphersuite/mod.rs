//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use evercrypt::prelude::*;
use hpke::prelude::*;
use serde::{Deserialize, Serialize};

// re-export for other parts of the library when we can use it
pub(crate) use hpke::{HPKEKeyPair, HPKEPrivateKey, HPKEPublicKey};

mod ciphersuites;
mod codec;
pub(crate) mod signable;
use ciphersuites::*;

use crate::utils::random_u32;

#[cfg(test)]
mod test_ciphersuite;

pub const NONCE_BYTES: usize = 12;
pub const REUSE_GUARD_BYTES: usize = 4;
pub const CHACHA_KEY_BYTES: usize = 32;
pub const AES_128_KEY_BYTES: usize = 16;
pub const AES_256_KEY_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CiphersuiteName {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
}

#[derive(Debug)]
pub enum HKDFError {
    InvalidLength,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<0..2^16-1>;
///     opaque ciphertext<0..2^16-1>;
/// } HPKECiphertext;
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct HpkeCiphertext {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ===

#[derive(Debug)]
pub enum AEADError {
    EncryptionError,
    DecryptionError,
    WrongKeyLength,
}

#[derive(Debug, PartialEq)]
pub struct AeadKey {
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ReuseGuard {
    value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Samples a fresh reuse guard uniformly at random.
    pub fn new_from_random() -> Self {
        let reuse_guard: [u8; REUSE_GUARD_BYTES] = random_u32().to_be_bytes();
        ReuseGuard { value: reuse_guard }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AeadNonce {
    value: [u8; NONCE_BYTES],
}

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    value: Vec<u8>,
}

#[derive(Clone)]
pub struct SignaturePrivateKey {
    ciphersuite: Ciphersuite,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignaturePublicKey {
    ciphersuite: Ciphersuite,
    value: Vec<u8>,
}

#[derive(Clone)]
pub struct SignatureKeypair {
    ciphersuite: Ciphersuite,
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
}

#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature: SignatureMode,
    hpke: Hpke,
    hpke_kem: HpkeKemMode,
    hpke_kdf: HpkeKdfMode,
    hpke_aead: HpkeAeadMode,
    aead: AeadMode,
    hash: DigestMode,
    hmac: HmacMode,
}

// Cloning a ciphersuite sets up a new one to make sure we don't accidentally
// carry over anything we don"t want to.
impl Clone for Ciphersuite {
    fn clone(&self) -> Self {
        Self::new(self.name)
    }
}

impl Ciphersuite {
    /// Create a new ciphersuite from the given `name`.
    pub fn new(name: CiphersuiteName) -> Self {
        let hpke_kem = get_kem_from_suite(&name).unwrap();
        let hpke_kdf = get_hpke_kdf_from_suite(&name);
        let hpke_aead = get_hpke_aead_from_suite(&name);

        Ciphersuite {
            name,
            signature: get_signature_from_suite(&name),
            hpke: Hpke::new(Mode::Base, hpke_kem, hpke_kdf, hpke_aead),
            hpke_kem,
            hpke_kdf,
            hpke_aead,
            aead: get_aead_from_suite(&name),
            hash: get_hash_from_suite(&name),
            hmac: get_kdf_from_suite(&name),
        }
    }

    /// Get the name of this ciphersuite.
    pub fn name(&self) -> CiphersuiteName {
        self.name
    }

    /// Create a new signature key pair and return it.
    pub fn new_signature_keypair(&self) -> SignatureKeypair {
        let (sk, pk) = match signature_key_gen(self.signature) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => panic!("Key generation really shouldn't fail. {:?}", e),
        };
        SignatureKeypair {
            ciphersuite: self.clone(),
            private_key: SignaturePrivateKey {
                value: sk.to_vec(),
                ciphersuite: self.clone(),
            },
            public_key: SignaturePublicKey {
                value: pk.to_vec(),
                ciphersuite: self.clone(),
            },
        }
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(self.hash, payload)
    }

    /// Get the length of the used hash algorithm.
    pub(crate) fn hash_length(&self) -> usize {
        get_digest_size(self.hash)
    }

    /// HKDF extract.
    pub(crate) fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_extract(self.hmac, salt, ikm)
    }

    /// HKDF expand
    pub(crate) fn hkdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, HKDFError> {
        let key = hkdf_expand(self.hmac, prk, info, okm_len);
        if key.is_empty() {
            return Err(HKDFError::InvalidLength);
        }
        Ok(key)
    }

    /// AEAD encrypt `msg` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        let (ct, tag) = match aead_encrypt(self.aead, &key.as_slice(), msg, &nonce.value, aad) {
            Ok((ct, tag)) => (ct, tag),
            Err(_) => return Err(AEADError::EncryptionError),
        };
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        // TODO: don't hard-code tag bytes
        if ciphertext.len() < TAG_BYTES {
            return Err(AEADError::DecryptionError);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_BYTES);
        match aead_decrypt(self.aead, key.as_slice(), ct, tag, &nonce.value, aad) {
            Ok(pt) => Ok(pt),
            Err(_) => Err(AEADError::DecryptionError),
        }
    }

    /// Returns the key size of the used AEAD.
    pub(crate) fn aead_key_length(&self) -> usize {
        aead_key_size(&self.aead)
    }

    /// Returns the length of the nonce in the AEAD.
    pub(crate) fn aead_nonce_length(&self) -> usize {
        NONCE_BYTES
    }

    /// HPKE single-shot encryption of `ptxt` to `pk_r`, using `info` and `aad`.
    pub(crate) fn hpke_seal(
        &self,
        pk_r: &HPKEPublicKey,
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext {
        let (kem_output, ciphertext) = self
            .hpke
            .seal(&pk_r, info, aad, ptxt, None, None, None)
            .unwrap();
        HpkeCiphertext {
            kem_output,
            ciphertext,
        }
    }

    /// HPKE single-shot decryption of `input` with `sk_r`, using `info` and `aad`.
    pub(crate) fn hpke_open(
        &self,
        input: &HpkeCiphertext,
        sk_r: &HPKEPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        self.hpke
            .open(
                &input.kem_output,
                &sk_r,
                info,
                aad,
                &input.ciphertext,
                None,
                None,
                None,
            )
            .unwrap()
    }

    /// Generate a new HPKE key pair and return it.
    pub(crate) fn derive_hpke_keypair(&self, ikm: &[u8]) -> HPKEKeyPair {
        self.hpke.derive_key_pair(ikm)
    }
}

impl AeadKey {
    /// Build a new key for an AEAD from `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> AeadKey {
        AeadKey {
            value: bytes.to_vec(),
        }
    }

    /// Get a slice to the key value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl AeadNonce {
    /// Build a new nonce for an AEAD from `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(bytes);
        AeadNonce { value: nonce }
    }

    /// Get a slice to the nonce value.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Xor the first bytes of the nonce with the reuse_guard.
    pub(crate) fn xor_with_reuse_guard(&mut self, reuse_guard: &ReuseGuard) {
        for i in 0..REUSE_GUARD_BYTES {
            self.value[i] ^= reuse_guard.value[i]
        }
    }
}

impl Signature {
    pub(crate) fn new_empty() -> Signature {
        Signature { value: vec![] }
    }
}

impl SignatureKeypair {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        self.private_key.sign(&payload)
    }

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> bool {
        self.public_key.verify(signature, payload)
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, SignaturePublicKey) {
        (self.private_key, self.public_key)
    }
}

impl PartialEq for SignaturePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl SignaturePublicKey {
    /// Create a new signature public key from raw key bytes.
    pub fn new(bytes: Vec<u8>, ciphersuite: Ciphersuite) -> Self {
        Self {
            value: bytes,
            ciphersuite,
        }
    }
    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> bool {
        verify(
            self.ciphersuite.signature,
            Some(self.ciphersuite.hash),
            &self.value,
            &signature.value,
            payload,
        )
        .unwrap()
    }
}

impl SignaturePrivateKey {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        let (hash, nonce) = match self.ciphersuite.signature {
            SignatureMode::Ed25519 => (None, None),
            SignatureMode::P256 => (Some(self.ciphersuite.hash), Some(p256_ecdsa_random_nonce())),
        };
        match sign(
            self.ciphersuite.signature,
            hash,
            &self.value,
            payload,
            nonce.as_ref(),
        ) {
            Ok(s) => Ok(Signature { value: s }),
            Err(e) => Err(e),
        }
    }
}

/// Make sure that xoring works by xoring a nonce with a reuse guard, testing if
/// it has changed, xoring it again and testing that it's back in its original
/// state.
#[test]
fn test_xor() {
    let reuse_guard: ReuseGuard = ReuseGuard::new_from_random();
    let original_nonce = AeadNonce::from_slice(get_random_vec(NONCE_BYTES).as_slice());
    let mut nonce = original_nonce.clone();
    nonce.xor_with_reuse_guard(&reuse_guard);
    assert_ne!(
        original_nonce, nonce,
        "xoring with reuse_guard did not change the nonce"
    );
    nonce.xor_with_reuse_guard(&reuse_guard);
    assert_eq!(
        original_nonce, nonce,
        "xoring twice changed the original value"
    );
}
