//! This module contains the types and implementations for the
//! `PublicGroupState` and `PublicGroupStateTbs` structs of the MLS spec. The
//! `PublicGroupState` implements type-enforced verification using the set of
//! traits defined in the [`signable`](crate::ciphersuite::signable) module in
//! the same way as the `MlsPlaintext`.
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Serialize, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use crate::{
    ciphersuite::{
        hash_ref::KeyPackageRef,
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        HpkePublicKey, Signature,
    },
    error::LibraryError,
    extensions::Extension,
    group::*,
    versions::ProtocolVersion,
};

/// PublicGroupState as defined in the MLS specification as follows:
///
/// ```text
/// struct {
///     ProtocolVersion version = mls10;
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
#[derive(PartialEq, Eq, Debug, TlsSerialize, TlsSize)]
pub struct PublicGroupState {
    pub(crate) version: ProtocolVersion,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) confirmed_transcript_hash: TlsByteVecU8,
    pub(crate) group_context_extensions: TlsVecU32<Extension>,
    pub(crate) other_extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    pub(crate) signer: KeyPackageRef,
    pub(crate) signature: Signature,
}

/// The [`VerifiablePublicGroupState`] represents a [`PublicGroupState`] of which
/// the signature has not been verified. It implements the [`Verifiable`] trait
/// and can thus be turned into a [`PublicGroupState`] by calling `verify(...)`
/// with the [`Credential`](crate::credentials::Credential) corresponding
/// to the [`CredentialBundle`](crate::credentials::CredentialBundle) of the signer.
/// When receiving a serialized [`PublicGroupState`], it can thus only be
/// deserialized into a [`VerifiablePublicGroupState`], which can then be turned
/// into a [`PublicGroupState`] as described above.
#[derive(Debug, Clone, TlsSize, TlsDeserialize, TlsSerialize)]
pub struct VerifiablePublicGroupState {
    tbs: PublicGroupStateTbs,
    signature: Signature,
}

impl VerifiablePublicGroupState {
    /// Returns the `ProtocolVersion` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn version(&self) -> ProtocolVersion {
        self.tbs.version
    }

    /// Returns a reference to the `Ciphersuite` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn ciphersuite(&self) -> Ciphersuite {
        self.tbs.ciphersuite
    }

    /// Returns a reference to the `tree_hash` of the unverified
    /// `PublicGroupState`.
    pub(crate) fn tree_hash(&self) -> &[u8] {
        self.tbs.tree_hash.as_slice()
    }

    /// Returns a reference to the [`KeyPackageRef`] of the signer.
    pub(crate) fn signer(&self) -> &KeyPackageRef {
        &self.tbs.signer
    }

    /// Returns a reference to the non [`GroupContext`] extensions of the unverified
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
            signer: v.tbs.signer,
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
            signer: tbs.signer,
            signature,
        }
    }
}

impl Verifiable for VerifiablePublicGroupState {
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
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) confirmed_transcript_hash: TlsByteVecU8,
    pub(crate) group_context_extensions: TlsVecU32<Extension>,
    pub(crate) other_extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    pub(crate) signer: KeyPackageRef,
}

impl PublicGroupStateTbs {
    /// Creates a new `PublicGroupStateTbs` struct from the current internal state
    /// of the group.
    pub(crate) fn new(
        backend: &impl OpenMlsCryptoProvider,
        core_group: &CoreGroup,
    ) -> Result<Self, LibraryError> {
        let ciphersuite = core_group.ciphersuite();
        let external_pub = core_group
            .group_epoch_secrets()
            .external_secret()
            .derive_external_keypair(backend.crypto(), ciphersuite)
            .public;

        let group_id = core_group.group_id().clone();
        let epoch = core_group.context().epoch();
        let tree_hash = core_group.treesync().tree_hash().into();
        let interim_transcript_hash = core_group.interim_transcript_hash().into();
        let confirmed_transcript_hash = core_group.confirmed_transcript_hash().into();
        let other_extensions = core_group.other_extensions().into();

        Ok(PublicGroupStateTbs {
            version: core_group.version(),
            group_id,
            epoch,
            tree_hash,
            interim_transcript_hash,
            confirmed_transcript_hash,
            group_context_extensions: core_group.group_context_extensions().into(),
            other_extensions,
            external_pub: external_pub.into(),
            ciphersuite,
            signer: *core_group
                .key_package_ref()
                .ok_or_else(|| LibraryError::custom("missing key package ref"))?,
        })
    }
}

impl Signable for PublicGroupStateTbs {
    type SignedOutput = PublicGroupState;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}
