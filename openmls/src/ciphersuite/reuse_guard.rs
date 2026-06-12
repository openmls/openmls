use super::*;

#[cfg(feature = "virtual-clients-draft")]
use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    ciphersuite::aead::AeadNonce,
    components::vc_derivation_info::{ReuseGuardSecret, VirtualClientsError},
    error::LibraryError,
};
#[cfg(feature = "virtual-clients-draft")]
use openmls_traits::crypto::OpenMlsCrypto;

/// Re-use guard size.
pub(crate) const REUSE_GUARD_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct ReuseGuard {
    pub(in crate::ciphersuite) value: [u8; REUSE_GUARD_BYTES],
}

impl ReuseGuard {
    /// Returns the raw 4 bytes of the guard.
    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) fn bytes(&self) -> [u8; REUSE_GUARD_BYTES] {
        self.value
    }

    /// Samples a fresh reuse guard uniformly at random.
    pub(crate) fn try_from_random(rng: &impl OpenMlsRand) -> Result<Self, CryptoError> {
        Ok(Self {
            value: rng
                .random_array()
                .map_err(|_| CryptoError::InsufficientRandomness)?,
        })
    }

    /// Build a `reuse_guard` for a virtual-clients sender as specified by
    /// the mls-virtual-clients draft (Reuse Guard section). Picks a
    /// random `x` uniformly from the largest `N_e`-divisible prefix of
    /// `[0, 2^32)` with `x mod N_e == leaf_index_e`, then encrypts `x`
    /// under FF1-AES128 with `prp_key = ExpandWithLabel(reuse_guard_secret,
    /// "reuse guard", key_schedule_nonce, 16)`.
    ///
    /// `emulation_ciphersuite` is the emulation group's ciphersuite.
    /// `ratchet_nonce` is the pre-XOR per-message nonce produced by the
    /// higher-level group's key schedule.
    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) fn for_emulator_sender(
        crypto: &impl OpenMlsCrypto,
        rand: &impl OpenMlsRand,
        reuse_guard_secret: &ReuseGuardSecret,
        emulation_ciphersuite: openmls_traits::types::Ciphersuite,
        ratchet_nonce: &AeadNonce,
        emulation_leaf_index: LeafNodeIndex,
        emulation_group_size: TreeSize,
    ) -> Result<Self, ReuseGuardDerivationError> {
        let n_e = u64::from(emulation_group_size.leaf_count());
        let leaf_index_e = u64::from(emulation_leaf_index.u32());
        if n_e == 0 {
            return Err(ReuseGuardDerivationError::Library(LibraryError::custom(
                "emulation_group_size is zero",
            )));
        }
        if leaf_index_e >= n_e {
            return Err(ReuseGuardDerivationError::Library(LibraryError::custom(
                "emulation_leaf_index is out of range for the emulation group",
            )));
        }

        // Largest multiple of N_e that fits in 2^32. Sampling uniformly
        // from [0, full) and then computing `(r / n_e) * n_e +
        // leaf_index_e` keeps the distribution uniform over the support
        // {leaf_index_e, leaf_index_e + n_e, ..., full - n_e + leaf_index_e}.
        let full: u64 = (1u64 << 32) / n_e * n_e;
        debug_assert!(full > 0);
        let r = loop {
            let candidate = u32::from_be_bytes(
                rand.random_array::<4>()
                    .map_err(|_| LibraryError::custom("rand failure"))?,
            );
            let candidate_u64 = u64::from(candidate);
            if candidate_u64 < full {
                break candidate_u64;
            }
        };
        let x_u64 = r / n_e * n_e + leaf_index_e;
        debug_assert!(x_u64 < (1u64 << 32));
        debug_assert_eq!(x_u64 % n_e, leaf_index_e);
        let x = x_u64 as u32;

        let prp_key = reuse_guard_secret.derive_prp_key(
            crypto,
            emulation_ciphersuite,
            ratchet_nonce.raw_bytes(),
        )?;
        let permuted = crypto.ff1_aes128_encrypt(&prp_key, x).map_err(|e| {
            log::error!("vc: FF1 encryption of reuse_guard failed: {e:?}");
            ReuseGuardDerivationError::Library(LibraryError::custom("FF1 encrypt failed"))
        })?;
        Ok(Self {
            value: permuted.to_be_bytes(),
        })
    }
}

/// Errors returned by [`ReuseGuard::for_emulator_sender`].
#[cfg(feature = "virtual-clients-draft")]
#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub(crate) enum ReuseGuardDerivationError {
    #[error(transparent)]
    VirtualClients(#[from] VirtualClientsError),
    #[error(transparent)]
    Library(#[from] LibraryError),
}

#[cfg(all(test, feature = "virtual-clients-draft"))]
mod vc_tests {
    use super::*;
    use crate::ciphersuite::Secret;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::Ciphersuite;
    use openmls_traits::OpenMlsProvider as _;

    fn provider() -> OpenMlsRustCrypto {
        OpenMlsRustCrypto::default()
    }

    fn dummy_reuse_guard_secret(
        _p: &OpenMlsRustCrypto,
        ciphersuite: Ciphersuite,
    ) -> ReuseGuardSecret {
        let bytes = vec![0xa5u8; ciphersuite.hash_length()];
        ReuseGuardSecret::from_secret_for_tests(Secret::from_slice(&bytes))
    }

    /// `leaf_index_e >= N_e` is a malformed `EmulationEpochState`. The
    /// sender path catches it before drawing any randomness or running
    /// FF1.
    #[test]
    fn for_emulator_sender_rejects_leaf_index_out_of_range() {
        let p = provider();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let secret = dummy_reuse_guard_secret(&p, ciphersuite);
        let nonce = crate::ciphersuite::aead::AeadNonce::random(p.rand());
        let n_e = TreeSize::from_leaf_count(1);
        debug_assert_eq!(n_e.leaf_count(), 2);
        let err = ReuseGuard::for_emulator_sender(
            p.crypto(),
            p.rand(),
            &secret,
            ciphersuite,
            &nonce,
            LeafNodeIndex::new(5),
            n_e,
        )
        .expect_err("malformed leaf_index must not produce a guard");
        assert!(
            matches!(err, ReuseGuardDerivationError::Library(_)),
            "expected LibraryError, got {err:?}"
        );
    }
}
