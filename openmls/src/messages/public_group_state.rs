use hpke::HpkePublicKey;
use tls_codec::{Serialize, Size, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct, Verifiable, VerifiedStruct},
        CiphersuiteName, Signature,
    },
    extensions::Extension,
    group::{GroupEpoch, GroupId, MlsGroup},
    tree::index::LeafIndex,
};

/// This module contains the types and implementations for the
/// `PublicGroupState` and `PublicGroupStateTbs` structs of the MLS spec.

/// PublicGroupState
///
/// ```text
/// struct {
///     CipherSuite cipher_suite;
///     opaque group_id<0..255>;
///     uint64 epoch;
///     opaque tree_hash<0..255>;
///     opaque interim_transcript_hash<0..255>;
///     Extension extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
///     uint32 signer_index;
///     opaque signature<0..2^16-1>;
/// } PublicGroupState;
/// ```
#[derive(PartialEq, Debug, TlsSerialize, TlsSize)]
pub struct PublicGroupState {
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    pub(crate) signer_index: LeafIndex,
    pub(crate) signature: Signature,
}

#[derive(Debug, Clone, TlsSize, TlsDeserialize, TlsSerialize)]
pub struct VerifiablePublicGroupState {
    tbs: PublicGroupStateTbs,
    signature: Signature,
}

mod private_mod {
    pub struct Seal;

    impl Default for Seal {
        fn default() -> Self {
            Seal {}
        }
    }
}

impl VerifiedStruct<VerifiablePublicGroupState> for PublicGroupState {
    fn from_verifiable(v: VerifiablePublicGroupState, _seal: Self::SealingType) -> Self {
        Self {
            ciphersuite: v.tbs.ciphersuite,
            group_id: v.tbs.group_id,
            epoch: v.tbs.epoch,
            tree_hash: v.tbs.tree_hash,
            interim_transcript_hash: v.tbs.interim_transcript_hash,
            extensions: v.tbs.extensions,
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
            ciphersuite: tbs.ciphersuite,
            group_id: tbs.group_id,
            epoch: tbs.epoch,
            tree_hash: tbs.tree_hash,
            interim_transcript_hash: tbs.interim_transcript_hash,
            extensions: tbs.extensions,
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
///     Extension extensions<0..2^32-1>;
///     HPKEPublicKey external_pub;
/// } PublicGroupStateTBS;
/// ```
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Debug, Clone)]
pub(crate) struct PublicGroupStateTbs {
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) group_id: GroupId,
    pub(crate) epoch: GroupEpoch,
    pub(crate) tree_hash: TlsByteVecU8,
    pub(crate) interim_transcript_hash: TlsByteVecU8,
    pub(crate) extensions: TlsVecU32<Extension>,
    pub(crate) external_pub: HpkePublicKey,
    pub(crate) signer_index: LeafIndex,
}

impl PublicGroupStateTbs {
    /// Creates a new `PublicGroupStateTbs` struct from the current internal state
    /// of the group.
    pub(crate) fn new(mls_group: &MlsGroup) -> Self {
        let ciphersuite = mls_group.ciphersuite();
        let (_external_priv, external_pub) = mls_group
            .epoch_secrets()
            .external_secret()
            .derive_external_keypair(ciphersuite)
            .into_keys();

        let group_id = mls_group.group_id().clone();
        let epoch = mls_group.context().epoch();
        let tree_hash = mls_group.tree().tree_hash().into();
        let interim_transcript_hash = mls_group.interim_transcript_hash().into();
        let extensions = mls_group.extensions().into();

        PublicGroupStateTbs {
            group_id,
            epoch,
            tree_hash,
            interim_transcript_hash,
            extensions,
            external_pub,
            ciphersuite: ciphersuite.name(),
            signer_index: mls_group.tree().own_node_index(),
        }
    }
}

impl Signable for PublicGroupStateTbs {
    type SignedOutput = PublicGroupState;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}
