use super::*;

/// 7.1 Content Authentication
///
/// opaque MAC<V>;
#[derive(Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct Mac {
    pub(crate) mac_value: VLBytes,
}

impl PartialEq for Mac {
    // Constant time comparison.
    fn eq(&self, other: &Mac) -> bool {
        equal_ct(self.mac_value.as_slice(), other.mac_value.as_slice())
    }
}

impl Mac {
    /// HMAC-Hash(salt, IKM). For all supported ciphersuites this is the same
    /// HMAC that is also used in HKDF.
    /// Compute the HMAC on `salt` with key `ikm`.
    pub(crate) fn new(
        crypto: &impl OpenMlsCrypto,
        salt: &Secret,
        ikm: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Mac {
            mac_value: salt
                .hkdf_extract(
                    crypto,
                    &Secret::from_slice(ikm, salt.mls_version, salt.ciphersuite),
                )?
                .value
                .as_slice()
                .into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn flip_last_byte(&mut self) {
        let mut last_bits = self.mac_value.pop().expect("An unexpected error occurred.");
        last_bits ^= 0xff;
        self.mac_value.push(last_bits);
    }
}
