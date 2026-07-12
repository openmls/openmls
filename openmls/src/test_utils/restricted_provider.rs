//! A test provider that restricts the set of supported ciphersuites.
//!
//! [`RestrictedProvider`] delegates all crypto operations to [`RustCrypto`]
//! but overrides [`OpenMlsCrypto::supports`] and
//! [`OpenMlsCrypto::supported_ciphersuites`] to an explicit allowlist. This
//! makes it possible to test the library's unsupported-ciphersuite error
//! paths, which cannot be reached with the regular providers (they support
//! every ciphersuite the tests can pick).

use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto, RustCrypto};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
    OpenMlsProvider,
};
use tls_codec::SecretVLBytes;

/// A crypto provider that performs all operations via [`RustCrypto`] but only
/// claims support for an explicit allowlist of ciphersuites.
pub struct RestrictedCrypto {
    inner: RustCrypto,
    allowed: Vec<Ciphersuite>,
}

impl OpenMlsCrypto for RestrictedCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if self.allowed.contains(&ciphersuite) {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.allowed.clone()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hmac(hash_type, key, message)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        self.inner.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.inner.signature_key_gen(alg)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.inner.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.inner.hpke_setup_sender_and_export(
            config,
            pk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        self.inner.hpke_setup_receiver_and_export(
            config,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        self.inner.derive_hpke_keypair(config, ikm)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_open_psk(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner
            .hpke_open_psk(config, input, sk_r, info, aad, psk, psk_id)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_seal_psk_resolved_aad<F, E>(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        ptxt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        aad_builder: F,
    ) -> Result<HpkeCiphertext, openmls_traits::crypto::HpkeSealPskResolvedAadError<E>>
    where
        Self: Sized,
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        self.inner
            .hpke_seal_psk_resolved_aad(config, pk_r, info, ptxt, psk, psk_id, aad_builder)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_encrypt(&self, key: &[u8; 16], plaintext: u32) -> Result<u32, CryptoError> {
        self.inner.ff1_aes128_encrypt(key, plaintext)
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn ff1_aes128_decrypt(&self, key: &[u8; 16], ciphertext: u32) -> Result<u32, CryptoError> {
        self.inner.ff1_aes128_decrypt(key, ciphertext)
    }
}

/// An [`OpenMlsProvider`] that only claims support for an explicit allowlist
/// of ciphersuites while remaining fully functional otherwise.
pub struct RestrictedProvider {
    crypto: RestrictedCrypto,
    inner: OpenMlsRustCrypto,
}

impl RestrictedProvider {
    /// Creates a provider that claims support for exactly the given
    /// ciphersuites.
    pub fn new(allowed: Vec<Ciphersuite>) -> Self {
        Self {
            crypto: RestrictedCrypto {
                inner: RustCrypto::default(),
                allowed,
            },
            inner: OpenMlsRustCrypto::default(),
        }
    }

    /// Returns an unrestricted provider sharing the same storage. Useful to
    /// set up state (e.g. key packages) that the restricted view then
    /// processes.
    pub fn inner(&self) -> &OpenMlsRustCrypto {
        &self.inner
    }
}

impl OpenMlsProvider for RestrictedProvider {
    type CryptoProvider = RestrictedCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        self.inner.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.inner.rand()
    }
}
