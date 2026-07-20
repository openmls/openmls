use super::*;

/// Re-use guard size.
pub(crate) const REUSE_GUARD_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct ReuseGuard {
    pub(in crate::ciphersuite) value: [u8; REUSE_GUARD_BYTES],
}
