//! This module contains validation functions for incoming messages
//! as defined in <https://github.com/openmls/openmls/wiki/Message-validation>

use std::collections::{BTreeSet, HashSet};

use openmls_traits::types::VerifiableCiphersuite;

use super::PublicGroup;
use crate::extensions::RequiredCapabilitiesExtension;
use crate::group::GroupContextExtensionsProposalValidationError;
use crate::prelude::LibraryError;
use crate::treesync::errors::LeafNodeValidationError;
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::{
        mls_auth_content_in::VerifiableAuthenticatedContentIn, ContentType, ProtocolMessage,
        Sender, WireFormat,
    },
    group::{
        errors::{ExternalCommitValidationError, ProposalValidationError, ValidationError},
        past_secrets::MessageSecretsStore,
        Member, ProposalQueue,
    },
    messages::{
        proposals::{Proposal, ProposalOrRefType, ProposalType},
        Commit,
    },
    schedule::errors::PskError,
};

impl PublicGroup {
    // === Messages ===

    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    pub(crate) fn validate_framing(
        &self,
        message: &ProtocolMessage,
    ) -> Result<(), ValidationError> {
        // ValSem002
        if message.group_id() != self.group_id() {
            return Err(ValidationError::WrongGroupId);
        }

        // ValSem003: Check boundaries for the epoch
        // We differentiate depending on the content type
        match message.content_type() {
            // For application messages we allow messages for older epochs as well
            ContentType::Application => {
                if message.epoch() > self.group_context().epoch() {
                    log::error!(
                        "Wrong Epoch: message.epoch() {} > {} self.group_context().epoch()",
                        message.epoch(),
                        self.group_context().epoch()
                    );
                    return Err(ValidationError::WrongEpoch);
                }
            }
            // For all other messages we only only accept the current epoch
            _ => {
                if message.epoch() != self.group_context().epoch() {
                    log::error!(
                        "Wrong Epoch: message.epoch() {} != {} self.group_context().epoch()",
                        message.epoch(),
                        self.group_context().epoch()
                    );
                    return Err(ValidationError::WrongEpoch);
                }
            }
        }

        Ok(())
    }

    /// Checks the following semantic validation:
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem009
    pub(super) fn validate_verifiable_content(
        &self,
        verifiable_content: &VerifiableAuthenticatedContentIn,
        message_secrets_store_option: Option<&MessageSecretsStore>,
    ) -> Result<(), ValidationError> {
        // ValSem004
        let sender = verifiable_content.sender();
        if let Sender::Member(leaf_index) = sender {
            // If the sender is a member, it has to be in the tree, except if
            // it's an application message. Then it might be okay if it's in an
            // old secret tree instance, but we'll leave that to the CoreGroup
            // to validate.
            let is_in_secrets_store = if let Some(mss) = message_secrets_store_option {
                mss.epoch_has_leaf(verifiable_content.epoch(), *leaf_index)
            } else {
                false
            };
            if !self.treesync().is_leaf_in_tree(*leaf_index) && !is_in_secrets_store {
                return Err(ValidationError::UnknownMember);
            }
        }

        // ValSem005
        // Application messages must always be encrypted
        if verifiable_content.content_type() == ContentType::Application {
            if verifiable_content.wire_format() != WireFormat::PrivateMessage {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !verifiable_content.sender().is_member() {
                return Err(ValidationError::NonMemberApplicationMessage);
            }
        }

        // ValSem009
        if verifiable_content.content_type() == ContentType::Commit
            && verifiable_content.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }

        Ok(())
    }

    // === Proposals ===

    /// Validate key uniqueness. This function implements the following checks:
    ///  - ValSem101: Add Proposal: Signature public key in proposals must be unique among proposals & members
    ///  - ValSem102: Add Proposal: Init key in proposals must be unique among proposals
    ///  - ValSem103: Add Proposal: Encryption key in proposals must be unique among proposals & members
    ///  - ValSem104: Add Proposal: Init key and encryption key must be different
    ///  - ValSem110: Update Proposal: Encryption key must be unique among proposals & members
    ///  - ValSem206: Commit: Path leaf node encryption key must be unique among proposals & members
    ///  - ValSem207: Commit: Path encryption keys must be unique among proposals & members
    pub(crate) fn validate_key_uniqueness(
        &self,
        proposal_queue: &ProposalQueue,
        commit: Option<&Commit>,
    ) -> Result<(), ProposalValidationError> {
        let mut signature_key_set = HashSet::new();
        let mut init_key_set = HashSet::new();
        let mut encryption_key_set = HashSet::new();

        let remove_proposals = HashSet::<LeafNodeIndex>::from_iter(
            proposal_queue
                .remove_proposals()
                .map(|remove_proposal| remove_proposal.remove_proposal().removed),
        );

        // Initialize the sets with the current members, filtered by the
        // remove proposals.
        for Member {
            index,
            encryption_key,
            signature_key,
            ..
        } in self.treesync().full_leave_members()
        {
            if !remove_proposals.contains(&index) {
                signature_key_set.insert(signature_key);
                encryption_key_set.insert(encryption_key);
            }
        }

        // Collect signature keys from add proposals
        let signature_keys = proposal_queue.add_proposals().map(|add_proposal| {
            add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .signature_key()
                .as_slice()
                .to_vec()
        });

        // Collect encryption keys from add proposals, update proposals, the
        // commit leaf node and path keys
        let encryption_keys = proposal_queue
            .add_proposals()
            .map(|add_proposal| {
                add_proposal
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .encryption_key()
                    .key()
                    .as_slice()
                    .to_vec()
            })
            .chain(proposal_queue.update_proposals().map(|update_proposal| {
                update_proposal
                    .update_proposal()
                    .leaf_node()
                    .encryption_key()
                    .key()
                    .as_slice()
                    .to_vec()
            }))
            .chain(commit.and_then(|commit| {
                commit
                    .path
                    .as_ref()
                    .map(|path| path.leaf_node().encryption_key().as_slice().to_vec())
            }))
            .chain(
                commit
                    .iter()
                    .filter_map(|commit| {
                        commit.path.as_ref().map(|path| {
                            path.nodes()
                                .iter()
                                .map(|node| node.encryption_key().as_slice().to_vec())
                        })
                    })
                    .flatten(),
            );

        // Collect init keys from add proposals
        let init_keys = proposal_queue.add_proposals().map(|add_proposal| {
            add_proposal
                .add_proposal()
                .key_package()
                .hpke_init_key()
                .as_slice()
                .to_vec()
        });

        // Validate uniqueness of signature keys
        //  - ValSem101
        for signature_key in signature_keys {
            if !signature_key_set.insert(signature_key) {
                return Err(ProposalValidationError::DuplicateSignatureKey);
            }
        }

        // Validate uniqueness of encryption keys
        //  - ValSem103
        //  - ValSem104
        //  - ValSem110
        //  - ValSem206
        //  - ValSem207
        for encryption_key in encryption_keys {
            if init_key_set.contains(&encryption_key) {
                return Err(ProposalValidationError::InitEncryptionKeyCollision);
            }
            if !encryption_key_set.insert(encryption_key) {
                return Err(ProposalValidationError::DuplicateEncryptionKey);
            }
        }

        // Validate uniqueness of init keys
        //  - ValSem102
        //  - ValSem104
        for init_key in init_keys {
            if encryption_key_set.contains(&init_key) {
                return Err(ProposalValidationError::InitEncryptionKeyCollision);
            }
            if !init_key_set.insert(init_key) {
                return Err(ProposalValidationError::DuplicateInitKey);
            }
        }

        Ok(())
    }

    /// Validate capablities. This function implements the following checks:
    /// - ValSem106: Add Proposal: required capabilities
    /// - ValSem109: Update Proposal: required capabilities
    pub(crate) fn validate_capabilities(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        // ValSem106/ValSem109: Check the required capabilities of the add & update
        // proposals This includes the following checks:
        // - Are ciphersuite & version listed in the `Capabilities` Extension?
        // - If a `RequiredCapabilitiesExtension` is present in the group: Is
        //   this supported by the node?
        // - Check that all extensions are contained in the capabilities.
        // - Check that the capabilities contain the leaf node's credential
        //   type.
        // - Check that the credential type is supported by all members of the
        //   group.
        // - Check that the capabilities field of this LeafNode indicates
        //   support for all the credential types currently in use by other
        //   members.

        // Extract the leaf nodes from the add & update proposals
        let leaf_nodes = proposal_queue
            .queued_proposals()
            .filter_map(|p| match p.proposal() {
                Proposal::Add(add_proposal) => Some(add_proposal.key_package().leaf_node()),
                Proposal::Update(update_proposal) => Some(update_proposal.leaf_node()),
                _ => None,
            });

        let mut group_leaf_nodes = self.treesync().full_leaves();

        for leaf_node in leaf_nodes {
            // Check if the ciphersuite and the version of the group are
            // supported.
            let capabilities = leaf_node.capabilities();
            if !capabilities
                .ciphersuites()
                .contains(&VerifiableCiphersuite::from(self.ciphersuite()))
                || !capabilities.versions().contains(&self.version())
            {
                return Err(ProposalValidationError::InsufficientCapabilities);
            }

            // If there is a required capabilities extension, check if that one
            // is supported.
            if let Some(required_capabilities) =
                self.group_context().extensions().required_capabilities()
            {
                // Check if all required capabilities are supported.
                capabilities
                    .supports_required_capabilities(required_capabilities)
                    .map_err(|_| ProposalValidationError::InsufficientCapabilities)?;
            }

            // Check that all extensions are contained in the capabilities.
            if !capabilities.contain_extensions(leaf_node.extensions()) {
                return Err(ProposalValidationError::InsufficientCapabilities);
            }

            // Check that the capabilities contain the leaf node's credential type.
            if !capabilities.contains_credential(&leaf_node.credential().credential_type()) {
                return Err(ProposalValidationError::InsufficientCapabilities);
            }

            // Check that the credential type is supported by all members of the group.
            if !group_leaf_nodes.all(|node| {
                node.capabilities()
                    .contains_credential(&leaf_node.credential().credential_type())
            }) {
                return Err(ProposalValidationError::InsufficientCapabilities);
            }

            // Check that the capabilities field of this LeafNode indicates
            // support for all the credential types currently in use by other
            // members.
            if !group_leaf_nodes
                .all(|node| capabilities.contains_credential(&node.credential().credential_type()))
            {
                return Err(ProposalValidationError::InsufficientCapabilities);
            }
        }
        Ok(())
    }

    /// Validate Add proposals. This function implements the following checks:
    ///  - ValSem105: Add Proposal: Ciphersuite & protocol version must match the group
    pub(crate) fn validate_add_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        let add_proposals = proposal_queue.add_proposals();

        for add_proposal in add_proposals {
            // ValSem105: Check if ciphersuite and version of the group are correct:
            if add_proposal.add_proposal().key_package().ciphersuite() != self.ciphersuite()
                || add_proposal.add_proposal().key_package().protocol_version() != self.version()
            {
                return Err(ProposalValidationError::InvalidAddProposalCiphersuiteOrVersion);
            }
        }
        Ok(())
    }

    /// Validate Remove proposals. This function implements the following checks:
    ///  - ValSem107: Remove Proposal: Removed member must be unique among proposals
    ///  - ValSem108: Remove Proposal: Removed member must be an existing group member
    pub(crate) fn validate_remove_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        let remove_proposals = proposal_queue.remove_proposals();

        let mut removes_set = HashSet::new();

        for remove_proposal in remove_proposals {
            let removed = remove_proposal.remove_proposal().removed();
            // ValSem107
            if !removes_set.insert(removed) {
                return Err(ProposalValidationError::DuplicateMemberRemoval);
            }

            // ValSem108
            if !self.treesync().is_leaf_in_tree(removed) {
                return Err(ProposalValidationError::UnknownMemberRemoval);
            }
        }

        Ok(())
    }

    /// Validate Update proposals. This function implements the following checks:
    ///  - ValSem111: Update Proposal: The sender of a full Commit must not include own update proposals
    ///  - ValSem112: Update Proposal: The sender of a standalone update proposal must be of type member
    /// TODO: #133 This validation must be updated according to Sec. 13.2
    pub(crate) fn validate_update_proposals(
        &self,
        proposal_queue: &ProposalQueue,
        committer: LeafNodeIndex,
    ) -> Result<(), ProposalValidationError> {
        // Check the update proposals from the proposal queue first
        let update_proposals = proposal_queue.update_proposals();

        for update_proposal in update_proposals {
            // ValSem112
            // The sender of a standalone update proposal must be of type member
            if let Sender::Member(sender_index) = update_proposal.sender() {
                // ValSem111
                // The sender of a full Commit must not include own update proposals
                if committer == *sender_index {
                    return Err(ProposalValidationError::CommitterIncludedOwnUpdate);
                }
            } else {
                return Err(ProposalValidationError::UpdateFromNonMember);
            }
        }
        Ok(())
    }

    /// Validate PreSharedKey proposals.
    ///
    /// This method implements the following checks:
    ///
    /// * ValSem401: The nonce of a PreSharedKeyID must have length KDF.Nh.
    /// * ValSem402: PSK in proposal must be of type Resumption (with usage Application) or External.
    /// * ValSem403: Proposal list must not contain multiple PreSharedKey proposals that reference the same PreSharedKeyID.
    pub(crate) fn validate_pre_shared_key_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        // ValSem403 (1/2)
        // TODO(#1335): Duplicate proposals are (likely) filtered.
        //              Let's do this check here until we haven't made sure.
        let mut visited_psk_ids = BTreeSet::new();

        for proposal in proposal_queue.psk_proposals() {
            let psk_id = proposal.psk_proposal().clone().into_psk_id();

            // ValSem401
            // ValSem402
            let psk_id = psk_id.validate_in_proposal(self.ciphersuite())?;

            // ValSem403 (2/2)
            if !visited_psk_ids.contains(&psk_id) {
                visited_psk_ids.insert(psk_id);
            } else {
                return Err(PskError::Duplicate { first: psk_id }.into());
            }
        }

        Ok(())
    }

    /// Validate constraints on an external commit. This function implements the following checks:
    ///  - ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
    ///  - ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
    ///  - ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
    pub(super) fn validate_external_commit(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ExternalCommitValidationError> {
        let count_external_init_proposals = proposal_queue
            .filtered_by_type(ProposalType::ExternalInit)
            .count();
        if count_external_init_proposals == 0 {
            // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
            return Err(ExternalCommitValidationError::NoExternalInitProposals);
        } else if count_external_init_proposals > 1 {
            // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
            return Err(ExternalCommitValidationError::MultipleExternalInitProposals);
        }

        // ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
        let contains_denied_proposal = proposal_queue.queued_proposals().any(|p| {
            let is_inline = p.proposal_or_ref_type() == ProposalOrRefType::Proposal;
            let is_allowed_type = matches!(
                p.proposal(),
                Proposal::ExternalInit(_) | Proposal::Remove(_) | Proposal::PreSharedKey(_)
            );
            is_inline && !is_allowed_type
        });
        if contains_denied_proposal {
            return Err(ExternalCommitValidationError::InvalidInlineProposals);
        }

        // If a Remove proposal is present,
        // the credential in the LeafNode MUST present a set of
        // identifiers that is acceptable to the application for
        // the removed participant.
        // This MUST be checked by the application.

        Ok(())
    }

    /// Returns a [`LeafNodeValidationError`] if an [`ExtensionType`]
    /// in `extensions` is not supported by a leaf in this tree.
    pub(crate) fn validate_group_context_extensions_proposal(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), GroupContextExtensionsProposalValidationError> {
        let iter = proposal_queue.filtered_by_type(ProposalType::GroupContextExtensions);

        for (i, queued_proposal) in iter.enumerate() {
            // There must at most be one group context extionsion proposal. Return an error if there are more
            if i > 0 {
                return Err(GroupContextExtensionsProposalValidationError::TooManyGCEProposals);
            }

            match queued_proposal.proposal() {
                Proposal::GroupContextExtensions(extensions) => {
                    let required_capabilities_in_proposal =
                        extensions.extensions().required_capabilities();

                    // Prepare the empty required capabilities in case there is no
                    // RequiredCapabilitiesExtension in the proposal
                    let default_required_capabilities =
                        RequiredCapabilitiesExtension::new(&[], &[], &[]);

                    // If there is a RequiredCapabilitiesExtension in the proposal, validate it and
                    // use that. Otherwise, use the empty default one.
                    let required_capabilities = match required_capabilities_in_proposal {
                        Some(required_capabilities_new) => {
                            // If a group context extensions proposal updates the required capabilities, we
                            // need to check that these are satisfied for all existing members of the group.
                            self.check_extension_support(required_capabilities_new.extension_types()).map_err(|_| GroupContextExtensionsProposalValidationError::RequiredExtensionNotSupportedByAllMembers)?;
                            required_capabilities_new
                        }
                        None => &default_required_capabilities,
                    };

                    // Make sure that all other extensions are known to be supported, by checking
                    // that they are included in the required capabilities.
                    let all_extensions_are_in_required_capabilities: bool = extensions
                        .extensions()
                        .iter()
                        .map(|ext| ext.extension_type())
                        .all(|ext_type| {
                            required_capabilities.requires_extension_type_support(ext_type)
                        });

                    if !all_extensions_are_in_required_capabilities {
                        return Err(GroupContextExtensionsProposalValidationError::ExtensionNotInRequiredCapabilities);
                    }
                }
                _ => {
                    return Err(GroupContextExtensionsProposalValidationError::LibraryError(
                        LibraryError::custom(
                            "found non-gce proposal when filtered for gce proposals",
                        ),
                    ))
                }
            }
        }

        Ok(())
    }

    /// Returns a [`LeafNodeValidationError`] if an [`ExtensionType`]
    /// in `extensions` is not supported by a leaf in this tree.
    pub(crate) fn check_extension_support(
        &self,
        extensions: &[crate::extensions::ExtensionType],
    ) -> Result<(), LeafNodeValidationError> {
        for leaf in self.treesync().full_leaves() {
            leaf.check_extension_support(extensions)?;
        }
        Ok(())
    }
}
