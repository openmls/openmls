//! A crypto/rand provider exposing the *previous* version's trait interface,
//! backed by the *current* libcrux crypto provider. For use in `compat_tests` only.
//!
//! The migration compat tests drive a previous-version and the current-version
//! OpenMLS stack in the same process. Depending on a previous-version libcrux
//! crypto provider (`openmls_libcrux_crypto_0_7` / `_0_8`) alongside the current
//! one (`openmls_libcrux_crypto_current`) pulls in two incompatible `libcrux`
//! versions, which cannot be resolved together.
//!
//! To avoid that, this module provides a single [`CryptoProvider`] that wraps the
//! *current* libcrux `CryptoProvider` and re-implements the previous version's
//! [`OpenMlsCrypto`](openmls_traits_compat::crypto::OpenMlsCrypto) and
//! [`OpenMlsRand`](openmls_traits_compat::random::OpenMlsRand) traits on top of
//! it. Every operation is delegated to the current provider; only the trait's
//! argument and result types are translated at the boundary.
//!
//! The two trait versions' crypto types are structurally identical but nominally
//! distinct: they come from different `openmls_traits` crate versions, and the
//! `tls_codec` types they wrap (`VLBytes`, `SecretVLBytes`) come from different,
//! semver-incompatible `tls_codec` versions (the current line uses 0.5, the
//! previous line 0.4). So every value crossing the boundary is converted, via the
//! free `*_to_current` / `*_to_compat` helpers.
//!
//! This provider is aliased to `openmls_libcrux_crypto_compat` at each use site,
//! so it drops in wherever the previous-version libcrux provider was used.

use openmls_libcrux_crypto_current::CryptoProvider as Inner;

use openmls_traits::crypto::OpenMlsCrypto as CurrentCrypto;
use openmls_traits::random::OpenMlsRand as CurrentRand;
use openmls_traits::types as cur;

// The previous version's traits crate, selected by the active migration feature.
// Exactly one is active at a time (each `storage_migration_*` feature turns on its
// matching traits crate), matching the aliasing in `test_storage_provider`.
#[cfg(feature = "storage_migration_0_7")]
use openmls_traits_0_4_1 as openmls_traits_compat;
#[cfg(feature = "storage_migration_0_8")]
use openmls_traits_0_5_0 as openmls_traits_compat;

#[cfg(feature = "compat_0_8_1")]
use openmls_0_8_1::prelude::tls_codec as tls_codec_compat;

#[cfg(feature = "compat_0_7_4")]
use openmls_0_7_4::prelude::tls_codec as tls_codec_compat;

use openmls_traits_compat::types as compat;

// The previous line's `SecretVLBytes`, taken from the previous-version crate's
// `tls_codec` re-export (0.4) so we can name it in the previous-version trait
// signatures below. It is a *different* type from the current line's 0.5
// `SecretVLBytes`, so return values are bridged through their bytes for conversion
// between the two types (see the `as_slice()` + `.into()` conversions below).
use tls_codec_compat::SecretVLBytes;

/// A previous-version crypto/rand provider backed by the current libcrux provider.
pub struct CryptoProvider {
    inner: Inner,
}

impl CryptoProvider {
    /// Instantiate the wrapper, initializing the inner (current) libcrux provider.
    pub fn new() -> Result<Self, cur::CryptoError> {
        Ok(Self {
            inner: Inner::new()?,
        })
    }
}

// === Type conversions (previous-version <-> current) ===

/// Map a current [`CryptoError`](cur::CryptoError) to its previous-version
/// counterpart. The two enums have identical variants.
fn err_to_compat(e: cur::CryptoError) -> compat::CryptoError {
    use compat::CryptoError as K;
    use cur::CryptoError as C;
    match e {
        C::CryptoLibraryError => K::CryptoLibraryError,
        C::AeadDecryptionError => K::AeadDecryptionError,
        C::HpkeDecryptionError => K::HpkeDecryptionError,
        C::HpkeEncryptionError => K::HpkeEncryptionError,
        C::UnsupportedSignatureScheme => K::UnsupportedSignatureScheme,
        C::KdfLabelTooLarge => K::KdfLabelTooLarge,
        C::KdfSerializationError => K::KdfSerializationError,
        C::HkdfOutputLengthInvalid => K::HkdfOutputLengthInvalid,
        C::InsufficientRandomness => K::InsufficientRandomness,
        C::InvalidSignature => K::InvalidSignature,
        C::UnsupportedAeadAlgorithm => K::UnsupportedAeadAlgorithm,
        C::UnsupportedKdf => K::UnsupportedKdf,
        C::InvalidLength => K::InvalidLength,
        C::UnsupportedHashAlgorithm => K::UnsupportedHashAlgorithm,
        C::SignatureEncodingError => K::SignatureEncodingError,
        C::SignatureDecodingError => K::SignatureDecodingError,
        C::SenderSetupError => K::SenderSetupError,
        C::ReceiverSetupError => K::ReceiverSetupError,
        C::ExporterError => K::ExporterError,
        C::UnsupportedCiphersuite => K::UnsupportedCiphersuite,
        C::TlsSerializationError => K::TlsSerializationError,
        C::TooMuchData => K::TooMuchData,
        C::SigningError => K::SigningError,
        C::InvalidPublicKey => K::InvalidPublicKey,
    }
}

/// Convert a previous-version ciphersuite to the current one via its IANA value.
fn cs_to_current(cs: compat::Ciphersuite) -> Result<cur::Ciphersuite, compat::CryptoError> {
    cur::Ciphersuite::try_from(u16::from(cs))
        .map_err(|_| compat::CryptoError::UnsupportedCiphersuite)
}

/// Convert a current ciphersuite back to the previous version's enum, dropping any
/// the previous version does not know (none of the supported ones, in practice).
fn cs_to_compat(cs: cur::Ciphersuite) -> Option<compat::Ciphersuite> {
    compat::Ciphersuite::try_from(u16::from(cs)).ok()
}

fn hash_to_current(h: compat::HashType) -> cur::HashType {
    match h {
        compat::HashType::Sha2_256 => cur::HashType::Sha2_256,
        compat::HashType::Sha2_384 => cur::HashType::Sha2_384,
        compat::HashType::Sha2_512 => cur::HashType::Sha2_512,
    }
}

fn aead_to_current(a: compat::AeadType) -> cur::AeadType {
    match a {
        compat::AeadType::Aes128Gcm => cur::AeadType::Aes128Gcm,
        compat::AeadType::Aes256Gcm => cur::AeadType::Aes256Gcm,
        compat::AeadType::ChaCha20Poly1305 => cur::AeadType::ChaCha20Poly1305,
    }
}

fn sig_to_current(s: compat::SignatureScheme) -> Result<cur::SignatureScheme, compat::CryptoError> {
    cur::SignatureScheme::try_from(s as u16)
        .map_err(|_| compat::CryptoError::UnsupportedSignatureScheme)
}

fn kem_to_current(k: compat::HpkeKemType) -> Result<cur::HpkeKemType, compat::CryptoError> {
    Ok(match k {
        compat::HpkeKemType::DhKemP256 => cur::HpkeKemType::DhKemP256,
        compat::HpkeKemType::DhKemP384 => cur::HpkeKemType::DhKemP384,
        compat::HpkeKemType::DhKemP521 => cur::HpkeKemType::DhKemP521,
        compat::HpkeKemType::DhKem25519 => cur::HpkeKemType::DhKem25519,
        compat::HpkeKemType::DhKem448 => cur::HpkeKemType::DhKem448,
        // XWing is only present in the current enum under a PQ feature that the
        // migration tests do not enable, so it has no current counterpart here.
        _ => return Err(compat::CryptoError::UnsupportedCiphersuite),
    })
}

fn kdf_to_current(k: compat::HpkeKdfType) -> cur::HpkeKdfType {
    match k {
        compat::HpkeKdfType::HkdfSha256 => cur::HpkeKdfType::HkdfSha256,
        compat::HpkeKdfType::HkdfSha384 => cur::HpkeKdfType::HkdfSha384,
        compat::HpkeKdfType::HkdfSha512 => cur::HpkeKdfType::HkdfSha512,
    }
}

fn hpke_aead_to_current(a: compat::HpkeAeadType) -> cur::HpkeAeadType {
    match a {
        compat::HpkeAeadType::AesGcm128 => cur::HpkeAeadType::AesGcm128,
        compat::HpkeAeadType::AesGcm256 => cur::HpkeAeadType::AesGcm256,
        compat::HpkeAeadType::ChaCha20Poly1305 => cur::HpkeAeadType::ChaCha20Poly1305,
        compat::HpkeAeadType::Export => cur::HpkeAeadType::Export,
    }
}

fn hpke_config_to_current(c: compat::HpkeConfig) -> Result<cur::HpkeConfig, compat::CryptoError> {
    Ok(cur::HpkeConfig(
        kem_to_current(c.0)?,
        kdf_to_current(c.1),
        hpke_aead_to_current(c.2),
    ))
}

/// Rewrap a previous-version HPKE ciphertext as the current struct.
///
/// XXX: The `VLBytes` fields come from different `tls_codec` versions (current 0.5
/// vs previous 0.4), so they are bridged through their bytes (`as_slice()` + `.into()`)
/// for conversion between the two types.
fn ciphertext_to_current(c: &compat::HpkeCiphertext) -> cur::HpkeCiphertext {
    cur::HpkeCiphertext {
        kem_output: c.kem_output.as_slice().into(),
        ciphertext: c.ciphertext.as_slice().into(),
    }
}

fn ciphertext_to_compat(c: cur::HpkeCiphertext) -> compat::HpkeCiphertext {
    compat::HpkeCiphertext {
        kem_output: c.kem_output.as_slice().into(),
        ciphertext: c.ciphertext.as_slice().into(),
    }
}

impl openmls_traits_compat::crypto::OpenMlsCrypto for CryptoProvider {
    fn supports(&self, ciphersuite: compat::Ciphersuite) -> Result<(), compat::CryptoError> {
        CurrentCrypto::supports(&self.inner, cs_to_current(ciphersuite)?).map_err(err_to_compat)
    }

    fn supported_ciphersuites(&self) -> Vec<compat::Ciphersuite> {
        CurrentCrypto::supported_ciphersuites(&self.inner)
            .into_iter()
            .filter_map(cs_to_compat)
            .collect()
    }

    fn hkdf_extract(
        &self,
        hash_type: compat::HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, compat::CryptoError> {
        // XXX: bridge the current (0.5) `SecretVLBytes` to the previous (0.4) one
        // through its bytes for conversion between the two `tls_codec` types.
        CurrentCrypto::hkdf_extract(&self.inner, hash_to_current(hash_type), salt, ikm)
            .map(|s| SecretVLBytes::from(s.as_slice()))
            .map_err(err_to_compat)
    }

    fn hmac(
        &self,
        hash_type: compat::HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, compat::CryptoError> {
        CurrentCrypto::hmac(&self.inner, hash_to_current(hash_type), key, message)
            .map(|s| SecretVLBytes::from(s.as_slice()))
            .map_err(err_to_compat)
    }

    fn hkdf_expand(
        &self,
        hash_type: compat::HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, compat::CryptoError> {
        CurrentCrypto::hkdf_expand(&self.inner, hash_to_current(hash_type), prk, info, okm_len)
            .map(|s| SecretVLBytes::from(s.as_slice()))
            .map_err(err_to_compat)
    }

    fn hash(
        &self,
        hash_type: compat::HashType,
        data: &[u8],
    ) -> Result<Vec<u8>, compat::CryptoError> {
        CurrentCrypto::hash(&self.inner, hash_to_current(hash_type), data).map_err(err_to_compat)
    }

    fn aead_encrypt(
        &self,
        alg: compat::AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, compat::CryptoError> {
        CurrentCrypto::aead_encrypt(&self.inner, aead_to_current(alg), key, data, nonce, aad)
            .map_err(err_to_compat)
    }

    fn aead_decrypt(
        &self,
        alg: compat::AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, compat::CryptoError> {
        CurrentCrypto::aead_decrypt(&self.inner, aead_to_current(alg), key, ct_tag, nonce, aad)
            .map_err(err_to_compat)
    }

    fn signature_key_gen(
        &self,
        alg: compat::SignatureScheme,
    ) -> Result<(Vec<u8>, Vec<u8>), compat::CryptoError> {
        CurrentCrypto::signature_key_gen(&self.inner, sig_to_current(alg)?).map_err(err_to_compat)
    }

    fn verify_signature(
        &self,
        alg: compat::SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), compat::CryptoError> {
        CurrentCrypto::verify_signature(&self.inner, sig_to_current(alg)?, data, pk, signature)
            .map_err(err_to_compat)
    }

    fn sign(
        &self,
        alg: compat::SignatureScheme,
        data: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, compat::CryptoError> {
        CurrentCrypto::sign(&self.inner, sig_to_current(alg)?, data, key).map_err(err_to_compat)
    }

    fn hpke_seal(
        &self,
        config: compat::HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<compat::HpkeCiphertext, compat::CryptoError> {
        CurrentCrypto::hpke_seal(
            &self.inner,
            hpke_config_to_current(config)?,
            pk_r,
            info,
            aad,
            ptxt,
        )
        .map(ciphertext_to_compat)
        .map_err(err_to_compat)
    }

    fn hpke_open(
        &self,
        config: compat::HpkeConfig,
        input: &compat::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, compat::CryptoError> {
        CurrentCrypto::hpke_open(
            &self.inner,
            hpke_config_to_current(config)?,
            &ciphertext_to_current(input),
            sk_r,
            info,
            aad,
        )
        .map_err(err_to_compat)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: compat::HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(compat::KemOutput, compat::ExporterSecret), compat::CryptoError> {
        // `KemOutput` is `Vec<u8>` on both sides; only `ExporterSecret` is rewrapped.
        CurrentCrypto::hpke_setup_sender_and_export(
            &self.inner,
            hpke_config_to_current(config)?,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
        .map(|(kem_output, exporter)| (kem_output, compat::ExporterSecret::from(exporter.to_vec())))
        .map_err(err_to_compat)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: compat::HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<compat::ExporterSecret, compat::CryptoError> {
        CurrentCrypto::hpke_setup_receiver_and_export(
            &self.inner,
            hpke_config_to_current(config)?,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
        .map(|exporter| compat::ExporterSecret::from(exporter.to_vec()))
        .map_err(err_to_compat)
    }

    fn derive_hpke_keypair(
        &self,
        config: compat::HpkeConfig,
        ikm: &[u8],
    ) -> Result<compat::HpkeKeyPair, compat::CryptoError> {
        CurrentCrypto::derive_hpke_keypair(&self.inner, hpke_config_to_current(config)?, ikm)
            .map(|kp| compat::HpkeKeyPair {
                private: compat::HpkePrivateKey::from(kp.private.to_vec()),
                public: kp.public,
            })
            .map_err(err_to_compat)
    }
}

impl openmls_traits_compat::random::OpenMlsRand for CryptoProvider {
    // The inner provider's error type already satisfies the trait bound
    // (`std::error::Error + Debug`), so it is reused directly.
    type Error = openmls_libcrux_crypto_current::RandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        CurrentRand::random_array::<N>(&self.inner)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        CurrentRand::random_vec(&self.inner, len)
    }
}
