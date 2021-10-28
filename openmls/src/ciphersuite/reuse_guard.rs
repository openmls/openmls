use super::*;

#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReuseGuard {
    pub(in crate::ciphersuite) value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Samples a fresh reuse guard uniformly at random.
    pub fn from_random(crypto: &impl OpenMlsCryptoProvider) -> Self {
        Self {
            value: crypto.rand().random_array().unwrap(),
        }
    }
}
