//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use log::error;

use evercrypt::prelude::*;
use hpke::prelude::*;
pub(crate) use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};

// re-export for other parts of the library when we can use it
pub(crate) use hpke::{HPKEKeyPair, HPKEPrivateKey, HPKEPublicKey};

mod ciphersuites;
mod codec;
mod errors;
pub(crate) mod signable;
use ciphersuites::*;
pub(crate) use errors::*;
mod ser;

use crate::config::{Config, ConfigError};
use crate::group::GroupContext;
use crate::schedule::ExporterSecret;
use crate::schedule::SenderDataSecret;
use crate::schedule::WelcomeSecret;
use crate::utils::random_u32;

#[cfg(test)]
mod test_ciphersuite;

pub(crate) const NONCE_BYTES: usize = 12;
pub(crate) const REUSE_GUARD_BYTES: usize = 4;
pub(crate) const TAG_BYTES: usize = 16;

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

implement_enum_display!(CiphersuiteName);

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<0..2^16-1>;
///     opaque ciphertext<0..2^16-1>;
/// } HPKECiphertext;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct HpkeCiphertext {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[cfg(test)]
impl HpkeCiphertext {
    /// This function flips the last byte of the ciphertext.
    pub fn flip_last_byte(&mut self) {
        let mut last_bits = self.ciphertext.pop().unwrap();
        last_bits ^= 0xff;
        self.ciphertext.push(last_bits);
    }
}

/// `KdfLabel` is later serialized and used in the `label` field of
/// `kdf_expand_label`.
struct KdfLabel {
    length: u16,
    label: String,
    context: Vec<u8>,
}

impl KdfLabel {
    pub fn serialized_label(context: &[u8], label: &str, length: usize) -> Vec<u8> {
        // TODO: This should throw an error. Generally, keys length should be
        // checked. (see #228).
        if length > u16::MAX.into() {
            panic!("Library error: Trying to derive a key with a too large length field!")
        }
        let full_label = "mls10 ".to_owned() + label;
        let kdf_label = KdfLabel {
            length: length as u16,
            label: full_label,
            context: context.to_vec(),
        };
        kdf_label.serialize()
    }
}

/// A struct to contain secrets. This is to provide better visibility into where
/// and how secrets are used and to avoid passing secrets in their raw
/// representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Secret {
    value: Vec<u8>,
}

impl Secret {
    // TODO: The only reason we still need this, is because ConfirmationTag is
    // currently not a MAC, but a Secret. This should be solved when we're up to
    // spec, i.e. with issue #147.
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.value.clone()
    }

    /// Randomly sample a fresh `Secret`.
    pub(crate) fn random(length: usize) -> Self {
        Secret {
            value: get_random_vec(length),
        }
    }

    /// Expand a `Secret` to a new `Secret` of length `length` including a
    /// `label` and a `context`.
    pub fn kdf_expand_label(
        &self,
        ciphersuite: &Ciphersuite,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Secret {
        let info = KdfLabel::serialized_label(context, label, length);
        ciphersuite.hkdf_expand(self, &info, length).unwrap()
    }

    /// Derive a new `Secret` from the this one by expanding it with the given
    /// `label` and an empty `context`.
    pub fn derive_secret(&self, ciphersuite: &Ciphersuite, label: &str) -> Secret {
        self.kdf_expand_label(ciphersuite, label, &[], ciphersuite.hash_length())
    }
}

impl Default for Secret {
    fn default() -> Self {
        Secret { value: vec![] }
    }
}

static EMPTY_SECRET: Secret = Secret { value: vec![] };

impl Default for &Secret {
    fn default() -> Self {
        &EMPTY_SECRET
    }
}

impl From<Vec<u8>> for Secret {
    fn from(bytes: Vec<u8>) -> Self {
        Secret { value: bytes }
    }
}

impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        Secret {
            value: bytes.to_vec(),
        }
    }
}

impl ExporterSecret {
    /// Derive a `Secret` from the exporter secret. We return `Vec<u8>` here, so
    /// it can be used outside of OpenMLS. This function is made available for
    /// use from the outside through [`crate::group::mls_group::export_secret`].
    pub(crate) fn derive_exported_secret(
        &self,
        ciphersuite: &Ciphersuite,
        label: &str,
        group_context: &GroupContext,
        key_length: usize,
    ) -> Vec<u8> {
        let context = &group_context.serialize();
        let context_hash = &ciphersuite.hash(context);
        self.secret()
            .derive_secret(ciphersuite, label)
            .kdf_expand_label(ciphersuite, label, context_hash, key_length)
            .value
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AeadKey {
    aead_mode: AeadMode,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReuseGuard {
    value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Samples a fresh reuse guard uniformly at random.
    pub fn from_random() -> Self {
        let reuse_guard: [u8; REUSE_GUARD_BYTES] = random_u32().to_be_bytes();
        ReuseGuard { value: reuse_guard }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AeadNonce {
    value: [u8; NONCE_BYTES],
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Signature {
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SignaturePrivateKey {
    ciphersuite: &'static Ciphersuite,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignaturePublicKey {
    ciphersuite: &'static Ciphersuite,
    value: Vec<u8>,
}

implement_persistence!(SignaturePublicKey, value);

#[derive(Clone)]
pub struct SignatureKeypair {
    ciphersuite: &'static Ciphersuite,
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
}

#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature: SignatureMode,
    hpke: Hpke,
    aead: AeadMode,
    hash: DigestMode,
    hmac: HmacMode,
}

impl std::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}", self.name))
    }
}

// Cloning a ciphersuite sets up a new one to make sure we don't accidentally
// carry over anything we don"t want to.
impl Clone for Ciphersuite {
    fn clone(&self) -> Self {
        Self::new(self.name).unwrap()
    }
}

// Ciphersuites are equal if they have the same name.
impl PartialEq for Ciphersuite {
    fn eq(&self, other: &Ciphersuite) -> bool {
        self.name == other.name
    }
}

impl Ciphersuite {
    /// Create a new ciphersuite from the given `name`.
    pub(crate) fn new(name: CiphersuiteName) -> Result<Self, ConfigError> {
        let hpke_kem = kem_from_suite(&name).unwrap();
        let hpke_kdf = hpke_kdf_from_suite(&name);
        let hpke_aead = hpke_aead_from_suite(&name);

        Ok(Ciphersuite {
            name,
            signature: signature_from_suite(&name)?,
            hpke: Hpke::new(Mode::Base, hpke_kem, hpke_kdf, hpke_aead),
            aead: aead_from_suite(&name),
            hash: hash_from_suite(&name),
            hmac: kdf_from_suite(&name),
        })
    }

    /// Get the name of this ciphersuite.
    pub fn name(&self) -> CiphersuiteName {
        self.name
    }

    /// Get the AEAD mode
    #[cfg(test)]
    pub(crate) fn aead(&self) -> AeadMode {
        self.aead
    }

    /// Create a new signature key pair and return it.
    pub(crate) fn new_signature_keypair(&'static self) -> Result<SignatureKeypair, CryptoError> {
        let (sk, pk) = match signature_key_gen(self.signature) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => {
                error!("Key generation really shouldn't fail. {:?}", e);
                return Err(CryptoError::CryptoLibraryError);
            }
        };
        Ok(SignatureKeypair {
            ciphersuite: self,
            private_key: SignaturePrivateKey {
                value: sk.to_vec(),
                ciphersuite: self,
            },
            public_key: SignaturePublicKey {
                value: pk.to_vec(),
                ciphersuite: self,
            },
        })
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
    pub(crate) fn hkdf_extract(&self, salt_option: Option<&Secret>, ikm: &Secret) -> Secret {
        let salt = salt_option.unwrap_or_default();
        Secret {
            value: hkdf_extract(self.hmac, salt.value.as_slice(), ikm.value.as_slice()),
        }
    }

    /// HKDF expand
    pub(crate) fn hkdf_expand(
        &self,
        prk: &Secret,
        info: &[u8],
        okm_len: usize,
    ) -> Result<Secret, HKDFError> {
        let key = hkdf_expand(self.hmac, &prk.value, info, okm_len);
        if key.is_empty() {
            return Err(HKDFError::InvalidLength);
        }
        Ok(Secret { value: key })
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

    /// HPKE single-shot encryption specifically to seal a Secret `secret` to
    /// `pk_r`, using `info` and `aad`.
    pub(crate) fn hpke_seal_secret(
        &self,
        pk_r: &HPKEPublicKey,
        info: &[u8],
        aad: &[u8],
        secret: &Secret,
    ) -> HpkeCiphertext {
        self.hpke_seal(pk_r, info, aad, &secret.value)
    }

    /// HPKE single-shot decryption of `input` with `sk_r`, using `info` and
    /// `aad`.
    pub(crate) fn hpke_open(
        &self,
        input: &HpkeCiphertext,
        sk_r: &HPKEPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
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
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    /// Derive a new HPKE keypair from a given Secret.
    pub(crate) fn derive_hpke_keypair(&self, ikm: &Secret) -> HPKEKeyPair {
        self.hpke.derive_key_pair(&ikm.value)
    }
}

impl AeadKey {
    /// Create an `AeadKey` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub(crate) fn from_secret(ciphersuite: &Ciphersuite, secret: Secret) -> Self {
        AeadKey {
            aead_mode: ciphersuite.aead,
            value: secret.value,
        }
    }

    /// Derive a new AEAD key from a `SenderDataSecret`.
    pub(crate) fn from_sender_data_secret(
        ciphersuite: &Ciphersuite,
        ciphertext: &[u8],
        sender_data_secret: &SenderDataSecret,
    ) -> Self {
        let key = sender_data_secret.secret().kdf_expand_label(
            ciphersuite,
            "key",
            &ciphertext,
            ciphersuite.aead_key_length(),
        );
        AeadKey {
            aead_mode: ciphersuite.aead,
            value: key.value,
        }
    }

    /// Derive a new AEAD key from a `WelcomeSecret`.
    pub(crate) fn from_welcome_secret(
        ciphersuite: &Ciphersuite,
        welcome_secret: &WelcomeSecret,
    ) -> AeadKey {
        let aead_secret = ciphersuite
            .hkdf_expand(
                &welcome_secret.secret(),
                b"key",
                ciphersuite.aead_key_length(),
            )
            .unwrap();
        AeadKey {
            aead_mode: ciphersuite.aead,
            value: aead_secret.value,
        }
    }

    #[cfg(test)]
    /// Generate a random AEAD Key
    pub fn from_random(aead_mode: AeadMode) -> Self {
        AeadKey {
            aead_mode,
            value: aead_key_gen(aead_mode),
        }
    }

    #[cfg(test)]
    /// Get a slice to the key value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Encrypt a payload under the AeadKey given a nonce.
    pub(crate) fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AeadError> {
        let (ct, tag) = aead_encrypt(
            self.aead_mode,
            &self.value.as_slice(),
            msg,
            &nonce.value,
            aad,
        )?;
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AeadError> {
        // TODO: don't hard-code tag bytes (Issue #205)
        if ciphertext.len() < TAG_BYTES {
            error!("Ciphertext is too short (less than {:?} bytes)", TAG_BYTES);
            return Err(AeadError::Decrypting);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_BYTES);
        aead_decrypt(
            self.aead_mode,
            self.value.as_slice(),
            ct,
            tag,
            &nonce.value,
            aad,
        )
    }
}

impl AeadNonce {
    /// Create an `AeadNonce` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub fn from_secret(secret: Secret) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(&secret.value);
        AeadNonce { value: nonce }
    }
    /// Derive a new AEAD nonce from a `SenderDataSecret`.
    pub(crate) fn from_sender_data_secret(
        ciphersuite: &Ciphersuite,
        ciphertext: &[u8],
        sender_data_secret: &SenderDataSecret,
    ) -> Self {
        let nonce_secret = sender_data_secret.secret().kdf_expand_label(
            ciphersuite,
            "nonce",
            &ciphertext,
            ciphersuite.aead_nonce_length(),
        );
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(nonce_secret.value.as_slice());
        AeadNonce { value: nonce }
    }

    /// Derive a new AEAD key from a `WelcomeSecret`.
    pub(crate) fn from_welcome_secret(
        ciphersuite: &Ciphersuite,
        welcome_secret: &WelcomeSecret,
    ) -> Self {
        let nonce_secret = ciphersuite
            .hkdf_expand(
                &welcome_secret.secret(),
                b"nonce",
                ciphersuite.aead_nonce_length(),
            )
            .unwrap();
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(nonce_secret.value.as_slice());
        AeadNonce { value: nonce }
    }

    /// Generate a new random nonce.
    pub fn from_random() -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(get_random_vec(NONCE_BYTES).as_slice());
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
    pub fn new(bytes: Vec<u8>, ciphersuite: CiphersuiteName) -> Result<Self, ConfigError> {
        Ok(Self {
            value: bytes,
            ciphersuite: Config::ciphersuite(ciphersuite)?,
        })
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
    let reuse_guard: ReuseGuard = ReuseGuard::from_random();
    let original_nonce = AeadNonce::from_random();
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
