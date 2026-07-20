//! # Messages
//!
//! This module defines types and logic for Commit and Welcome messages, as well
//! as Proposals and group info used in External Commits.

use openmls_traits::types::{Ciphersuite, HpkeCiphertext};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tls_codec::*;

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, *},
    schedule::{psk::PreSharedKeyId, JoinerSecret},
    treesync::treekem::{UpdatePath, UpdatePathIn},
};

pub(crate) mod codec;
pub mod external_proposals;
pub mod group_info;
pub mod proposals;
pub mod proposals_in;

use self::{proposals::*, proposals_in::ProposalOrRefIn};

/// Welcome message
///
/// This message is generated when a new member is added to a group.
/// The invited member can use this message to join the group using
/// [`StagedWelcome::new_from_welcome()`](crate::group::mls_group::StagedWelcome::new_from_welcome()).
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   CipherSuite cipher_suite;
///   EncryptedGroupSecrets secrets<V>;
///   opaque encrypted_group_info<V>;
/// } Welcome;
/// ```
#[derive(
    Clone, Debug, Eq, PartialEq, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct Welcome {
    cipher_suite: Ciphersuite,
    secrets: Vec<EncryptedGroupSecrets>,
    encrypted_group_info: VLBytes,
}

/// EncryptedGroupSecrets
///
/// This is part of a [`Welcome`] message. It can be used to correlate the correct secrets with each new member.
#[derive(
    Clone, Debug, Eq, PartialEq, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct EncryptedGroupSecrets {
    /// Key package reference of the new member
    new_member: KeyPackageRef,
    /// Ciphertext of the encrypted group secret
    encrypted_group_secrets: HpkeCiphertext,
}

// Crate-only types

/// Commit.
///
/// A Commit message initiates a new epoch for the group,
/// based on a collection of Proposals. It instructs group
/// members to update their representation of the state of
/// the group by applying the proposals and advancing the
/// key schedule.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     ProposalOrRef proposals<V>;
///     optional<UpdatePath> path;
/// } Commit;
/// ```
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct Commit {
    pub(crate) proposals: Vec<ProposalOrRef>,
    pub(crate) path: Option<UpdatePath>,
}

#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub(crate) struct CommitIn {
    proposals: Vec<ProposalOrRefIn>,
    path: Option<UpdatePathIn>,
}

/// Confirmation tag field of PublicMessage. For type safety this is a wrapper
/// around a `Mac`.
#[derive(
    Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
pub struct ConfirmationTag(pub(crate) Mac);

/// PathSecret
///
/// > 11.2.2. Welcoming New Members
///
/// ```text
/// struct {
///   opaque path_secret<1..255>;
/// } PathSecret;
/// ```
#[derive(
    Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub(crate) struct PathSecret {
    pub(crate) path_secret: Secret,
}

/// GroupSecrets
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///   opaque joiner_secret<V>;
///   optional<PathSecret> path_secret;
///   PreSharedKeyID psks<V>;
/// } GroupSecrets;
/// ```
#[derive(Debug, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub(crate) struct GroupSecrets {
    pub(crate) joiner_secret: JoinerSecret,
    pub(crate) path_secret: Option<PathSecret>,
    pub(crate) psks: Vec<PreSharedKeyId>,
}

#[derive(TlsSerialize, TlsSize)]
struct EncodedGroupSecrets<'a> {
    pub(crate) joiner_secret: &'a JoinerSecret,
    pub(crate) path_secret: Option<&'a PathSecret>,
    pub(crate) psks: &'a [PreSharedKeyId],
}

/// Error related to group secrets.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupSecretsError {
    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
    /// Malformed.
    #[error("Malformed.")]
    Malformed,
}
