use std::fmt::{Debug, Formatter};

use tls_codec::SecretVLBytes;

use super::{kdf_label::KdfLabel, *};

/// A struct to contain secrets. This is to provide better visibility into where
/// and how secrets are used and to avoid passing secrets in their raw
/// representation.
///
/// Note: This has a hand-written `Debug` implementation.
///       Please update as well when changing this struct.
#[derive(Clone, Serialize, Deserialize, Eq)]
pub(crate) struct Secret {
    pub(in crate::ciphersuite) value: SecretVLBytes,
}

impl Debug for Secret {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut ds = f.debug_struct("Secret");

        #[cfg(feature = "crypto-debug")]
        return ds.field("value", &self.value).finish();
        #[cfg(not(feature = "crypto-debug"))]
        ds.field("value", &"***").finish()
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self {
            value: Vec::new().into(),
        }
    }
}

impl PartialEq for Secret {
    // Constant time comparison.
    fn eq(&self, other: &Secret) -> bool {
        // These values can be considered public and checked before the actual
        // comparison.
        if self.value.as_slice().len() != other.value.as_slice().len() {
            log::error!("Incompatible secrets");
            log::trace!("  {}", self.value.as_slice().len());
            log::trace!("  {}", other.value.as_slice().len());
            return false;
        }
        equal_ct(self.value.as_slice(), other.value.as_slice())
    }
}

impl Secret {
    /// Randomly sample a fresh `Secret`.
    /// This default random initialiser uses the default Secret length of `hash_length`.
    /// The function can return a [`CryptoError`] if there is insufficient randomness.
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rand: &impl OpenMlsRand,
    ) -> Result<Self, CryptoError> {
        Ok(Secret {
            value: rand
                .random_vec(ciphersuite.hash_length())
                .map_err(|_| CryptoError::InsufficientRandomness)?
                .into(),
        })
    }

    /// Create an all zero secret.
    pub(crate) fn zero(ciphersuite: Ciphersuite) -> Self {
        Self {
            value: vec![0u8; ciphersuite.hash_length()].into(),
        }
    }

    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Secret {
            value: bytes.into(),
        }
    }

    /// HKDF extract where `self` is `salt`.
    pub(crate) fn hkdf_extract<'a>(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ikm_option: impl Into<Option<&'a Secret>>,
    ) -> Result<Self, CryptoError> {
        log::trace!("HKDF extract with");
        log_crypto!(trace, "  salt: {:x?}", self.value);
        let zero_secret = Self::zero(ciphersuite);
        let ikm = ikm_option.into().unwrap_or(&zero_secret);
        log_crypto!(trace, "  ikm:  {:x?}", ikm.value);

        Ok(Self {
            value: crypto.hkdf_extract(
                ciphersuite.hash_algorithm(),
                self.value.as_slice(),
                ikm.value.as_slice(),
            )?,
        })
    }

    /// HKDF expand where `self` is `prk`.
    pub(crate) fn hkdf_expand(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        info: &[u8],
        okm_len: usize,
    ) -> Result<Self, CryptoError> {
        let key = crypto
            .hkdf_expand(
                ciphersuite.hash_algorithm(),
                self.value.as_slice(),
                info,
                okm_len,
            )
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        if key.as_slice().is_empty() {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self { value: key })
    }

    /// Expand a `Secret` to a new `Secret` of length `length` including a
    /// `label` and a `context`.
    pub(crate) fn kdf_expand_label(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Secret, CryptoError> {
        let full_label = format!("MLS 1.0 {}", label);
        log::trace!(
            "KDF expand with label \"{}\" and {:?} with context {:x?}",
            &full_label,
            ciphersuite,
            context
        );
        let info = KdfLabel::serialized_label(context, full_label, length)?;
        log::trace!("  serialized info: {:x?}", info);
        log_crypto!(trace, "  secret: {:x?}", self.value);
        self.hkdf_expand(crypto, ciphersuite, &info, length)
    }

    /// Derive a new `Secret` from the this one by expanding it with the given
    /// `label` and an empty `context`.
    pub(crate) fn derive_secret(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        label: &str,
    ) -> Result<Secret, CryptoError> {
        log_crypto!(
            trace,
            "derive secret from {:x?} with label {}",
            self.value,
            label
        );
        self.kdf_expand_label(crypto, ciphersuite, label, &[], ciphersuite.hash_length())
    }

    /// Returns the inner bytes of a secret
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        log::trace!("Secret from slice");
        Secret {
            value: bytes.into(),
        }
    }
}
