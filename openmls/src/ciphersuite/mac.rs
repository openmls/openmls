use super::*;

/// A wrapper to contain MAC values that will be zeroed on drop.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    zeroize::ZeroizeOnDrop,
)]
pub(crate) struct MacValue(Vec<u8>);

impl From<Vec<u8>> for MacValue {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for MacValue {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// 7.1 Content Authentication
///
/// opaque MAC<V>;
#[derive(Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct Mac {
    pub(crate) mac_value: MacValue,
}

impl PartialEq for Mac {
    // Constant time comparison.
    fn eq(&self, other: &Mac) -> bool {
        equal_ct(&self.mac_value, &other.mac_value)
    }
}

impl Mac {
    /// HMAC-Hash(salt, IKM). For all supported ciphersuites this is the same
    /// HMAC that is also used in HKDF.
    /// Compute the HMAC on `salt` with key `ikm`.
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        salt: &Secret,
        ikm: &[u8],
    ) -> Result<Self, CryptoError> {
        let value = std::mem::take(
            &mut salt
                .hkdf_extract(
                    backend,
                    &Secret::from_slice(ikm, salt.mls_version, salt.ciphersuite),
                )?
                .value,
        );
        Ok(Mac {
            mac_value: value.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn flip_last_byte(&mut self) {
        let mut last_bits = self
            .mac_value
            .0
            .pop()
            .expect("An unexpected error occurred.");
        last_bits ^= 0xff;
        self.mac_value.0.push(last_bits);
    }
}
