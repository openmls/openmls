use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::Verifiable,
    error::LibraryError,
    extensions::{Extensions, RequiredCapabilitiesExtension},
    framing::InterimTranscriptHashInput,
    messages::{
        proposals::{Proposal, ProposalType},
        ConfirmationTag, GroupInfo, VerifiableGroupInfo,
    },
    treesync::{Node, TreeSync},
    versions::ProtocolVersion,
};

use self::errors::CreationFromExternalError;

use super::{update_interim_transcript_hash, GroupContext, GroupEpoch, GroupId};

pub mod errors;

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PublicGroup {
    treesync: TreeSync,
    group_context: GroupContext,
    interim_transcript_hash: Vec<u8>,
    // Most recent confirmation tag. Kept here for verification purposes.
    confirmation_tag: ConfirmationTag,
}

impl PublicGroup {
    pub fn from_external(
        backend: &impl OpenMlsCryptoProvider,
        nodes: &[Option<Node>],
        verifiable_group_info: VerifiableGroupInfo,
    ) -> Result<(Self, Extensions), CreationFromExternalError> {
        let ciphersuite = verifiable_group_info.ciphersuite();

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes(backend, ciphersuite, &nodes)?;

        let group_info: GroupInfo = {
            let signer_credential = treesync
                .leaf(verifiable_group_info.signer())
                .ok_or(CreationFromExternalError::UnknownSender)?
                .credential();

            verifiable_group_info
                .verify(
                    backend,
                    signer_credential.signature_key(),
                    ciphersuite.signature_algorithm(),
                )
                .map_err(|_| CreationFromExternalError::InvalidGroupInfoSignature)?
        };

        if treesync.tree_hash() != group_info.group_context().tree_hash() {
            return Err(CreationFromExternalError::TreeHashMismatch);
        }

        if group_info.group_context().protocol_version() != ProtocolVersion::Mls10 {
            return Err(CreationFromExternalError::UnsupportedMlsVersion);
        }

        let group_context = GroupContext::new(
            ciphersuite,
            group_info.group_context().group_id().clone(),
            group_info.group_context().epoch(),
            treesync.tree_hash().to_vec(),
            group_info
                .group_context()
                .confirmed_transcript_hash()
                .to_vec(),
            group_info.group_context().extensions().clone(),
        );

        let interim_transcript_hash = if group_context.epoch() == GroupEpoch::from(0) {
            vec![]
        } else {
            // New members compute the interim transcript hash using
            // the confirmation_tag field of the GroupInfo struct.
            update_interim_transcript_hash(
                ciphersuite,
                backend,
                &InterimTranscriptHashInput::from(group_info.confirmation_tag()),
                group_info.group_context().confirmed_transcript_hash(),
            )?
        };
        Ok((
            Self {
                treesync,
                group_context,
                interim_transcript_hash,
                confirmation_tag: group_info.confirmation_tag().clone(),
            },
            group_info.extensions().clone(),
        ))
    }

    /// Create a new PublicGroup from nodes and a [`GroupInfo`].
    pub(crate) fn new(
        treesync: TreeSync,
        group_context: GroupContext,
        initial_confirmation_tag: ConfirmationTag,
    ) -> Self {
        let interim_transcript_hash = vec![];

        PublicGroup {
            treesync,
            group_context,
            interim_transcript_hash,
            confirmation_tag: initial_confirmation_tag,
        }
    }

    /// Returns the leftmost free leaf index.
    ///
    /// For External Commits of the "resync" type, this returns the index
    /// of the sender.
    ///
    /// The proposals must be validated before calling this function.
    pub(crate) fn free_leaf_index<'a>(
        &self,
        mut inline_proposals: impl Iterator<Item = Option<&'a Proposal>>,
    ) -> Result<LeafNodeIndex, LibraryError> {
        // Leftmost free leaf in the tree
        let free_leaf_index = self.treesync().free_leaf_index();
        // Returns the first remove proposal (if there is one)
        let remove_proposal_option = inline_proposals
            .find(|proposal| match proposal {
                Some(p) => p.is_type(ProposalType::Remove),
                None => false,
            })
            .flatten();
        let leaf_index = if let Some(remove_proposal) = remove_proposal_option {
            if let Proposal::Remove(remove_proposal) = remove_proposal {
                let removed_index = remove_proposal.removed();
                if removed_index < free_leaf_index {
                    removed_index
                } else {
                    free_leaf_index
                }
            } else {
                return Err(LibraryError::custom("missing key package"));
            }
        } else {
            free_leaf_index
        };
        Ok(leaf_index)
    }
}

// Getters
impl PublicGroup {
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.group_context.ciphersuite()
    }

    pub fn version(&self) -> ProtocolVersion {
        self.group_context.protocol_version()
    }

    pub fn group_id(&self) -> &GroupId {
        self.group_context.group_id()
    }

    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    pub fn extensions(&self) -> &Extensions {
        self.group_context.extensions()
    }

    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.group_context.required_capabilities()
    }

    pub(crate) fn treesync(&self) -> &TreeSync {
        &self.treesync
    }

    pub fn interim_transcript_hash(&self) -> &[u8] {
        &self.interim_transcript_hash
    }

    pub fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.confirmation_tag
    }
}

// Setters
// TODO: Most of these should go away as soon as we do processing directly
// on the public group.
impl PublicGroup {
    pub(crate) fn treesync_mut(&mut self) -> &mut TreeSync {
        &mut self.treesync
    }

    pub fn set_group_context(&mut self, group_context: GroupContext) {
        self.group_context = group_context
    }

    pub fn set_interim_transcript_hash(&mut self, interim_transcript_hash: Vec<u8>) {
        self.interim_transcript_hash = interim_transcript_hash
    }
}

// Test and test-utils functions
impl PublicGroup {
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}
