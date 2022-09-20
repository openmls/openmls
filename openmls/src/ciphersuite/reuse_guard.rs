use super::*;

/// Re-use guard size.
pub(crate) const REUSE_GUARD_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ReuseGuard {
    pub(in crate::ciphersuite) value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Samples a fresh reuse guard uniformly at random.
    pub(crate) fn try_from_random(
        crypto: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            value: crypto
                .rand()
                .random_array()
                .map_err(|_| CryptoError::InsufficientRandomness)?,
        })
    }
}
