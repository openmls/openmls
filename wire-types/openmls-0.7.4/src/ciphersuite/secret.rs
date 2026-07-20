use std::fmt::{Debug, Formatter};

use tls_codec::SecretVLBytes;

use super::*;

/// A struct to contain secrets. This is to provide better visibility into where
/// and how secrets are used and to avoid passing secrets in their raw
/// representation.
///
/// Note: This has a hand-written `Debug` implementation.
///       Please update as well when changing this struct.
#[derive(Clone, Serialize, Deserialize)]
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

impl Secret {
    /// Create a new secret from a byte vector.
    #[cfg(feature = "migration-export")]
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Secret {
            value: bytes.into(),
        }
    }
}
