use tls_codec::SecretVLBytes;

use super::*;

/// The default NONCE size in bytes.
pub(crate) const NONCE_BYTES: usize = 12;

/// AEAD keys holding the plain key value and the AEAD algorithm type.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(Clone, PartialEq, Eq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub struct AeadKey {
    aead_mode: AeadType,
    value: SecretVLBytes,
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("aead_mode", &self.aead_mode)
            .field("value", &"***")
            .finish()
    }
}

/// AEAD Nonce
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct AeadNonce([u8; NONCE_BYTES]);

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for AeadNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AeadNonce").field(&"***").finish()
    }
}

impl AeadKey {
    /// Create an `AeadKey` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub(crate) fn from_secret(secret: Secret, ciphersuite: Ciphersuite) -> Self {
        log::trace!("AeadKey::from_secret with {}", ciphersuite);
        AeadKey {
            aead_mode: ciphersuite.aead_algorithm(),
            value: secret.value,
        }
    }

    #[cfg(test)]
    /// Generate a random AEAD Key
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        AeadKey {
            aead_mode: ciphersuite.aead_algorithm(),
            value: aead_key_gen(ciphersuite.aead_algorithm(), rng),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Get a slice to the key value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Encrypt a payload under the AeadKey given a nonce.
    pub(crate) fn aead_seal(
        &self,
        crypto: &impl OpenMlsCrypto,
        msg: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        crypto
            .aead_encrypt(self.aead_mode, self.value.as_slice(), msg, &nonce.0, aad)
            .map_err(|_| CryptoError::CryptoLibraryError)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        crypto
            .aead_decrypt(
                self.aead_mode,
                self.value.as_slice(),
                ciphertext,
                &nonce.0,
                aad,
            )
            .map_err(|_| CryptoError::AeadDecryptionError)
    }
}

impl AeadNonce {
    /// Create an `AeadNonce` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub(crate) fn from_secret(secret: Secret) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(secret.value.as_slice());
        Self(nonce)
    }

    /// Generate a new random nonce.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    #[cfg(test)]
    pub(crate) fn random(rng: &impl OpenMlsRand) -> Self {
        Self(rng.random_array().expect("Not enough entropy."))
    }

    /// Get a slice to the nonce value.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Xor the first bytes of the nonce with the reuse_guard.
    pub(crate) fn xor_with_reuse_guard(mut self, reuse_guard: &ReuseGuard) -> Self {
        log_crypto!(
            trace,
            "  XOR re-use guard {:x?}^{:x?}",
            self.0,
            reuse_guard.value
        );
        for i in 0..REUSE_GUARD_BYTES {
            self.0[i] ^= reuse_guard.value[i]
        }
        log_crypto!(trace, "    = {:x?}", self.0);
        self
    }
}

#[cfg(test)]
pub(crate) fn aead_key_gen(
    alg: openmls_traits::types::AeadType,
    rng: &impl OpenMlsRand,
) -> SecretVLBytes {
    match alg {
        openmls_traits::types::AeadType::Aes128Gcm => rng
            .random_vec(16)
            .expect("An unexpected error occurred.")
            .into(),
        openmls_traits::types::AeadType::Aes256Gcm
        | openmls_traits::types::AeadType::ChaCha20Poly1305 => rng
            .random_vec(32)
            .expect("An unexpected error occurred.")
            .into(),
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::test_utils::*;

    use super::*;

    /// Make sure that xoring works by xoring a nonce with a reuse guard, testing if
    /// it has changed, xoring it again and testing that it's back in its original
    /// state.
    #[openmls_test::openmls_test]
    fn test_xor() {
        let reuse_guard: ReuseGuard =
            ReuseGuard::try_from_random(provider.rand()).expect("An unexpected error occurred.");
        let original_nonce = AeadNonce::random(provider.rand());
        let xored_once = original_nonce.clone().xor_with_reuse_guard(&reuse_guard);
        assert_ne!(
            original_nonce, xored_once,
            "xoring with reuse_guard did not change the nonce"
        );
        let xored_twice = xored_once.xor_with_reuse_guard(&reuse_guard);
        assert_eq!(
            original_nonce, xored_twice,
            "xoring twice changed the original value"
        );
    }
}
