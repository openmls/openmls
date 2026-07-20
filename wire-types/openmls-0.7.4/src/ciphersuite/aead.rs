use tls_codec::SecretVLBytes;

use super::*;

/// The default NONCE size in bytes.
pub(crate) const NONCE_BYTES: usize = 12;

/// AEAD keys holding the plain key value and the AEAD algorithm type.
#[derive(Serialize, Deserialize)]
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
