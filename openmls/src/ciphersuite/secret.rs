use super::kdf_label::KdfLabel;
use super::*;

/// A struct to contain secrets. This is to provide better visibility into where
/// and how secrets are used and to avoid passing secrets in their raw
/// representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Secret {
    pub(in crate::ciphersuite) ciphersuite: Ciphersuite,
    pub(in crate::ciphersuite) value: Vec<u8>,
    pub(in crate::ciphersuite) mls_version: ProtocolVersion,
}

impl Default for Secret {
    fn default() -> Self {
        Self {
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            value: Vec::new(),
            mls_version: ProtocolVersion::default(),
        }
    }
}

impl PartialEq for Secret {
    // Constant time comparison.
    fn eq(&self, other: &Secret) -> bool {
        // These values can be considered public and checked before the actual
        // comparison.
        if self.ciphersuite != other.ciphersuite
            || self.mls_version != other.mls_version
            || self.value.len() != other.value.len()
        {
            log::error!("Incompatible secrets");
            log::trace!(
                "  {} {} {}",
                self.ciphersuite,
                self.mls_version,
                self.value.len()
            );
            log::trace!(
                "  {} {} {}",
                other.ciphersuite,
                other.mls_version,
                other.value.len()
            );
            return false;
        }
        equal_ct(&self.value, &other.value)
    }
}

impl Secret {
    /// Randomly sample a fresh `Secret`.
    /// This default random initialiser uses the default Secret length of `hash_length`.
    /// The function can return a [`CryptoError`] if there is insufficient randomness.
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCryptoProvider,
        version: impl Into<Option<ProtocolVersion>>,
    ) -> Result<Self, CryptoError> {
        let mls_version = version.into().unwrap_or_default();
        log::trace!(
            "Creating a new random secret for {:?} and {:?}",
            ciphersuite,
            mls_version
        );
        Ok(Secret {
            value: crypto
                .rand()
                .random_vec(ciphersuite.hash_length())
                .map_err(|_| CryptoError::InsufficientRandomness)?,
            mls_version,
            ciphersuite,
        })
    }

    /// Create an all zero secret.
    pub(crate) fn zero(ciphersuite: Ciphersuite, mls_version: ProtocolVersion) -> Self {
        Self {
            value: vec![0u8; ciphersuite.hash_length()],
            mls_version,
            ciphersuite,
        }
    }

    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(
        bytes: &[u8],
        mls_version: ProtocolVersion,
        ciphersuite: Ciphersuite,
    ) -> Self {
        Secret {
            value: bytes.to_vec(),
            mls_version,
            ciphersuite,
        }
    }

    /// HKDF extract where `self` is `salt`.
    pub(crate) fn hkdf_extract<'a>(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ikm_option: impl Into<Option<&'a Secret>>,
    ) -> Result<Self, CryptoError> {
        log::trace!("HKDF extract with {:?}", self.ciphersuite);
        log_crypto!(trace, "  salt: {:x?}", self.value);
        let zero_secret = Self::zero(self.ciphersuite, self.mls_version);
        let ikm = ikm_option.into().unwrap_or(&zero_secret);
        log_crypto!(trace, "  ikm:  {:x?}", ikm.value);

        // We don't return an error here to keep the error propagation from
        // blowing up. If this fails, something in the library is really wrong
        // and we can't recover from it.
        assert!(
            self.mls_version == ikm.mls_version,
            "{} != {}",
            self.mls_version,
            ikm.mls_version
        );
        assert!(
            self.ciphersuite == ikm.ciphersuite,
            "{} != {}",
            self.ciphersuite,
            ikm.ciphersuite
        );

        Ok(Self {
            value: backend.crypto().hkdf_extract(
                self.ciphersuite.hash_algorithm(),
                self.value.as_slice(),
                ikm.value.as_slice(),
            )?,
            mls_version: self.mls_version,
            ciphersuite: self.ciphersuite,
        })
    }

    /// HKDF expand where `self` is `prk`.
    pub(crate) fn hkdf_expand(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        info: &[u8],
        okm_len: usize,
    ) -> Result<Self, CryptoError> {
        let key = backend
            .crypto()
            .hkdf_expand(
                self.ciphersuite.hash_algorithm(),
                &self.value,
                info,
                okm_len,
            )
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        if key.is_empty() {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self {
            value: key,
            mls_version: self.mls_version,
            ciphersuite: self.ciphersuite,
        })
    }

    /// Expand a `Secret` to a new `Secret` of length `length` including a
    /// `label` and a `context`.
    pub(crate) fn kdf_expand_label(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Secret, CryptoError> {
        let full_label = format!("{} {}", self.mls_version, label);
        log::trace!(
            "KDF expand with label \"{}\" and {:?} with context {:x?}",
            &full_label,
            self.ciphersuite,
            context
        );
        let info = KdfLabel::serialized_label(context, full_label, length)?;
        log::trace!("  serialized context: {:x?}", info);
        log_crypto!(trace, "  secret: {:x?}", self.value);
        self.hkdf_expand(backend, &info, length)
    }

    /// Derive a new `Secret` from the this one by expanding it with the given
    /// `label` and an empty `context`.
    pub(crate) fn derive_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
    ) -> Result<Secret, CryptoError> {
        log_crypto!(
            trace,
            "derive secret from {:x?} with label {} and {:?}",
            self.value,
            label,
            self.ciphersuite
        );
        self.kdf_expand_label(backend, label, &[], self.ciphersuite.hash_length())
    }

    /// Update the ciphersuite and MLS version of this secret.
    /// Ideally we wouldn't need this function but the way decoding works right
    /// now this is the easiest for now.
    pub(crate) fn config(&mut self, ciphersuite: Ciphersuite, mls_version: ProtocolVersion) {
        self.ciphersuite = ciphersuite;
        self.mls_version = mls_version;
    }

    /// Returns the inner bytes of a secret
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }

    /// Returns the ciphersuite of the secret
    pub(crate) fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Returns the version of the secret. TODO: This function should go away
    /// when tackling issue #641.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.mls_version
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<&[u8]> for Secret {
    fn from(bytes: &[u8]) -> Self {
        log::trace!("Secret from slice");
        Secret {
            value: bytes.to_vec(),
            mls_version: ProtocolVersion::default(),
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        }
    }
}
