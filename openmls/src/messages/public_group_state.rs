//! This module contains the types and implementations for the
//! `PublicGroupState` and `PublicGroupStateTbs` structs of the MLS spec. The
//! `PublicGroupState` implements type-enforced verification in the same way as
//! the `MlsPlaintext` and as described in the [`OpenMLS Wiki`].
//!
//! [`OpenMLS Wiki`]: https://github.com/openmls/openmls/wiki/Signable
use openmls_traits::{types::CryptoError, OpenMlsCryptoProvider};
use tls_codec::{Serialize, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        CiphersuiteName, HpkePublicKey, Signature,
    },
    extensions::Extension,
    group::{GroupEpoch, GroupId, MlsGroup},
    prelude::ProtocolVersion,
    treesync::LeafIndex,
};

/// PublicGroupState as defined in the MLS specification as follows:
///
/// ```text
/// struct {
///     CipherSuite cipher_suite;
///     opaque group_id<0..255>;
///     uint64 epoch;
///     opaque tree_hash<0..255>;
///     opaque interim_transcript_hash<0..255>;
///     Extension group_context_extensions<0..2^32-1>;
///     Extension other_extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
///     uint32 signer_index;
///     opaque signature<0..2^16-1>;
/// } PublicGroupState;
/// ```
///
/// A `PublicGroupState` can be created by verifying a
/// `VerifiablePublicGroupState`.
#[derive(PartialEq, Debug, TlsSerialize, TlsSize)]
pub struct PublicGroupState {
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) confirmed_transcript_hash: TlsByteVecU8,
    pub(crate) group_context_extensions: TlsVecU32<Extension>,
    pub(crate) other_extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    // TODO: #541 replace signer_index with [`KeyPackageRef`]
    pub(crate) signer_index: LeafIndex,
    pub(crate) signature: Signature,
}

/// The `VerifiablePublicGroupState` represents a `PublicGroupState` of which
/// the signature has not been verified. It implements the `Verifiable` trait
/// and can thus be turned into a `PublicGroupState` by calling `verify(...)`
/// with the `Credential` corresponding to the `CredentialBundle` of the signer.
/// When receiving a serialized "PublicGroupState", it can thus only be
/// deserialized into a `VerifiablePublicGroupState`, which can then be turned
/// into a `PublicGroupState` as described above.
#[derive(Debug, Clone, TlsSize, TlsDeserialize, TlsSerialize)]
pub struct VerifiablePublicGroupState {
    tbs: PublicGroupStateTbs,
    signature: Signature,
}

impl VerifiablePublicGroupState {
    /// Get the `ProtocolVersion` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.tbs.version
    }

    /// Get a reference to the `Ciphersuite` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn ciphersuite(&self) -> CiphersuiteName {
        self.tbs.ciphersuite
    }

    /// Get a reference to the `tree_hash` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tbs.tree_hash.as_slice()
    }

    /// Get the `LeafIndex` of the signer of the unverified `PublicGroupState`.
    pub(crate) fn signer_index(&self) -> LeafIndex {
        self.tbs.signer_index
    }

    /// Get a reference to the non [`GroupContext`] extensions of the unverified
    /// `PublicGroupState`.
    pub(crate) fn other_extensions(&self) -> &[Extension] {
        self.tbs.other_extensions.as_slice()
    }
}

mod private_mod {
    #[derive(Default)]
    pub struct Seal;
}

impl VerifiedStruct<VerifiablePublicGroupState> for PublicGroupState {
    fn from_verifiable(v: VerifiablePublicGroupState, _seal: Self::SealingType) -> Self {
        Self {
            version: v.tbs.version,
            ciphersuite: v.tbs.ciphersuite,
            group_id: v.tbs.group_id,
            epoch: v.tbs.epoch,
            tree_hash: v.tbs.tree_hash,
            interim_transcript_hash: v.tbs.interim_transcript_hash,
            confirmed_transcript_hash: v.tbs.confirmed_transcript_hash,
            group_context_extensions: v.tbs.group_context_extensions,
            other_extensions: v.tbs.other_extensions,
            external_pub: v.tbs.external_pub,
            signer_index: v.tbs.signer_index,
            signature: v.signature,
        }
    }

    type SealingType = private_mod::Seal;
}

impl SignedStruct<PublicGroupStateTbs> for PublicGroupState {
    fn from_payload(tbs: PublicGroupStateTbs, signature: Signature) -> Self {
        Self {
            version: tbs.version,
            ciphersuite: tbs.ciphersuite,
            group_id: tbs.group_id,
            epoch: tbs.epoch,
            tree_hash: tbs.tree_hash,
            interim_transcript_hash: tbs.interim_transcript_hash,
            confirmed_transcript_hash: tbs.confirmed_transcript_hash,
            group_context_extensions: tbs.group_context_extensions,
            other_extensions: tbs.other_extensions,
            external_pub: tbs.external_pub,
            signer_index: tbs.signer_index,
            signature,
        }
    }
}

impl<'a> Verifiable for VerifiablePublicGroupState {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tbs.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// PublicGroupStateTBS
///
/// ```text
/// struct {
///     opaque group_id<0..255>;
///     uint64 epoch;
///     opaque tree_hash<0..255>;
///     opaque interim_transcript_hash<0..255>;
///     Extension group_context_extensions<0..2^32-1>;
///     Extension other_extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
/// } PublicGroupStateTBS;
/// ```
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Debug, Clone)]
pub(crate) struct PublicGroupStateTbs {
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) confirmed_transcript_hash: TlsByteVecU8,
    pub(crate) group_context_extensions: TlsVecU32<Extension>,
    pub(crate) other_extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    // TODO: #541 replace signer_index with [`KeyPackageRef`]
    pub(crate) signer_index: LeafIndex,
}

impl PublicGroupStateTbs {
    /// Creates a new `PublicGroupStateTbs` struct from the current internal state
    /// of the group.
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        mls_group: &MlsGroup,
    ) -> Result<Self, CryptoError> {
        let ciphersuite = mls_group.ciphersuite();
        let external_pub = mls_group
            .group_epoch_secrets()
            .external_secret()
            .derive_external_keypair(backend.crypto(), ciphersuite)
            .public;

        let group_id = mls_group.group_id().clone();
        let epoch = mls_group.context().epoch();
        let tree_hash = mls_group.treesync().tree_hash().into();
        let interim_transcript_hash = mls_group.interim_transcript_hash().into();
        let confirmed_transcript_hash = mls_group.confirmed_transcript_hash().into();
        let other_extensions = mls_group.other_extensions().into();

        Ok(PublicGroupStateTbs {
            version: mls_group.version(),
            group_id,
            epoch,
            tree_hash,
            interim_transcript_hash,
            confirmed_transcript_hash,
            group_context_extensions: mls_group.group_context_extensions().into(),
            other_extensions,
            external_pub: external_pub.into(),
            ciphersuite: ciphersuite.name(),
            signer_index: mls_group.treesync().own_leaf_index(),
        })
    }
}

impl Signable for PublicGroupStateTbs {
    type SignedOutput = PublicGroupState;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}
