use super::*;

/// The default NONCE size in bytes.
pub(crate) const NONCE_BYTES: usize = 12;

/// AEAD keys holding the plain key value and the AEAD algorithm type.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(Clone, PartialEq, Eq))]
pub struct AeadKey {
    aead_mode: AeadType,
    value: Vec<u8>,
}

/// AEAD Nonce
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub(crate) struct AeadNonce {
    // TODO: Use const generics here
    value: [u8; NONCE_BYTES],
}

impl AeadKey {
    /// Create an `AeadKey` from a `Secret`. TODO: This function should
    /// disappear when tackling issue #103.
    pub(crate) fn from_secret(secret: Secret) -> Self {
        log::trace!("AeadKey::from_secret with {}", secret.ciphersuite);
        AeadKey {
            aead_mode: secret.ciphersuite.aead_algorithm(),
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
        &self.value
    }

    /// Encrypt a payload under the AeadKey given a nonce.
    pub(crate) fn aead_seal(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        msg: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        backend
            .crypto()
            .aead_encrypt(
                self.aead_mode,
                self.value.as_slice(),
                msg,
                &nonce.value,
                aad,
            )
            .map_err(|_| CryptoError::CryptoLibraryError)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        backend
            .crypto()
            .aead_decrypt(
                self.aead_mode,
                self.value.as_slice(),
                ciphertext,
                &nonce.value,
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
        nonce.clone_from_slice(&secret.value);
        AeadNonce { value: nonce }
    }

    /// Generate a new random nonce.
    ///
    /// **NOTE: This has to wait until it can acquire the lock to get randomness!**
    /// TODO: This panics if another thread holding the rng panics.
    #[cfg(test)]
    pub(crate) fn random(rng: &impl OpenMlsCryptoProvider) -> Self {
        AeadNonce {
            value: rng.rand().random_array().expect("Not enough entropy."),
        }
    }

    /// Get a slice to the nonce value.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Xor the first bytes of the nonce with the reuse_guard.
    pub(crate) fn xor_with_reuse_guard(&mut self, reuse_guard: &ReuseGuard) {
        log_crypto!(
            trace,
            "  XOR re-use guard {:x?}^{:x?}",
            self.value,
            reuse_guard.value
        );
        for i in 0..REUSE_GUARD_BYTES {
            self.value[i] ^= reuse_guard.value[i]
        }
        log_crypto!(trace, "    = {:x?}", self.value);
    }
}

#[cfg(test)]
pub(crate) fn aead_key_gen(
    alg: openmls_traits::types::AeadType,
    rng: &impl OpenMlsRand,
) -> Vec<u8> {
    match alg {
        openmls_traits::types::AeadType::Aes128Gcm => {
            rng.random_vec(16).expect("An unexpected error occurred.")
        }
        openmls_traits::types::AeadType::Aes256Gcm
        | openmls_traits::types::AeadType::ChaCha20Poly1305 => {
            rng.random_vec(32).expect("An unexpected error occurred.")
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::test_utils::*;

    /// Make sure that xoring works by xoring a nonce with a reuse guard, testing if
    /// it has changed, xoring it again and testing that it's back in its original
    /// state.
    #[apply(backends)]
    fn test_xor(backend: &impl OpenMlsCryptoProvider) {
        let reuse_guard: ReuseGuard =
            ReuseGuard::try_from_random(backend).expect("An unexpected error occurred.");
        let original_nonce = AeadNonce::random(backend);
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
}
