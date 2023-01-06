//! This module contains validation functions for incoming messages
//! as defined in <https://github.com/openmls/openmls/wiki/Message-validation>

use std::collections::HashSet;

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::Sender,
    group::errors::ExternalCommitValidationError,
    group::errors::ValidationError,
    messages::proposals::{Proposal, ProposalOrRefType, ProposalType},
    treesync::node::leaf_node::LeafNode,
};

use super::{
    mls_content::ContentType, proposals::ProposalQueue, CoreGroup, Member, ProposalValidationError,
    ProtocolMessage, VerifiableAuthenticatedContent, WireFormat,
};

impl CoreGroup {
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
                if message.epoch() > self.context().epoch() {
                    return Err(ValidationError::WrongEpoch);
                }
            }
            // For all other messages we only only accept the current epoch
            _ => {
                if message.epoch() != self.context().epoch() {
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
    pub(crate) fn validate_verifiable_content(
        &self,
        verifiable_content: &VerifiableAuthenticatedContent,
    ) -> Result<(), ValidationError> {
        // ValSem004
        let sender = verifiable_content.sender();
        if let Sender::Member(leaf_index) = sender {
            // If the sender is a member, it has to be in the tree.
            // TODO: #133 Lookup of a leaf index in the old tree isn't very
            //       useful. Add a proper validation step here.
            if !self.treesync().is_leaf_in_tree(*leaf_index)
                && !self
                    .message_secrets_store
                    .epoch_has_leaf(verifiable_content.epoch(), *leaf_index)
            {
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

    /// Validate Add proposals. This function implements the following checks:
    ///  - ValSem100
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem103
    ///  - ValSem104
    ///  - ValSem106
    pub(crate) fn validate_add_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        let add_proposals = proposal_queue.add_proposals();

        let mut identity_set = HashSet::new();
        let mut signature_key_set = HashSet::new();
        let mut init_key_set = HashSet::new();
        let mut encryption_key_set = HashSet::new();
        for add_proposal in add_proposals {
            let identity = add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .credential()
                .identity()
                .to_vec();
            // ValSem100
            if !identity_set.insert(identity) {
                return Err(ProposalValidationError::DuplicateIdentityAddProposal);
            }
            let signature_key = add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .credential()
                .signature_key()
                .as_slice()
                .to_vec();
            // ValSem101
            if !signature_key_set.insert(signature_key) {
                return Err(ProposalValidationError::DuplicateSignatureKeyAddProposal);
            }

            let proposal_init_key = add_proposal
                .add_proposal()
                .key_package()
                .hpke_init_key()
                .as_slice()
                .to_vec();
            let proposal_encryption_key = add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .encryption_key();

            // ValSem113
            if proposal_init_key == proposal_encryption_key.as_ref() {
                return Err(ProposalValidationError::InitEncryptionKeyCollision);
            }

            // ValSem102
            if !init_key_set.insert(proposal_init_key) {
                return Err(ProposalValidationError::DuplicatePublicKeyAddProposal);
            }

            // ValSem114
            // Here we check that the encryption keys in the proposal are unique.
            // Further down we check that the encryption keys in the proposals
            // are not in the tree yet.
            if !encryption_key_set.insert(proposal_encryption_key.as_slice().to_vec()) {
                return Err(ProposalValidationError::DuplicatePublicKeyAddProposal);
            }

            // ValSem106: Check the required capabilities of the add proposals
            // This includes the following checks:
            // - Do ciphersuite and version match that of the group?
            // - Are the two listed in the `Capabilities` Extension?
            // - If a `RequiredCapabilitiesExtension` is present in the group:
            //   Does the key package advertise the capabilities required by that
            //   extension?

            // Check if ciphersuite and version of the group are correct.
            if add_proposal.add_proposal().key_package().ciphersuite() != self.ciphersuite()
                || add_proposal.add_proposal().key_package().protocol_version() != self.version()
            {
                log::error!("Tried to commit an Add proposal, where either the `Ciphersuite` or the `ProtocolVersion` is not compatible with the group.");

                return Err(ProposalValidationError::InsufficientCapabilities);
            }

            // Check if the ciphersuite and the version of the group are
            // supported.
            let capabilities = add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .capabilities();
            if !capabilities.ciphersuites().contains(&self.ciphersuite())
                || !capabilities.versions().contains(&self.version())
            {
                log::error!("Tried to commit an Add proposal, where either the group's `Ciphersuite` or the group's `ProtocolVersion` is not in the `KeyPackage`'s `Capabilities`.");
                return Err(ProposalValidationError::InsufficientCapabilities);
            }
            // If there is a required capabilities extension, check if that one
            // is supported.
            if let Some(required_capabilities) =
                self.group_context_extensions().required_capabilities()
            {
                // Check if all required capabilities are supported.
                if !capabilities.supports_required_capabilities(required_capabilities) {
                    log::error!("Tried to commit an Add proposal, where the `Capabilities` of the given `KeyPackage` do not fulfill the `RequiredCapabilities` of the group.");
                    return Err(ProposalValidationError::InsufficientCapabilities);
                }
            }
        }

        for Member {
            index,
            identity,
            encryption_key,
            signature_key,
        } in self.treesync().full_leave_members()
        {
            let has_remove_proposal = proposal_queue
                .remove_proposals()
                .any(|p| p.remove_proposal().removed == index);
            // ValSem103
            if identity_set.contains(&identity) && !has_remove_proposal {
                return Err(ProposalValidationError::ExistingIdentityAddProposal);
            }
            // ValSem104
            if signature_key_set.contains(&signature_key) && !has_remove_proposal {
                return Err(ProposalValidationError::ExistingSignatureKeyAddProposal);
            }
            // ValSem114
            if encryption_key_set.contains(&encryption_key) {
                return Err(ProposalValidationError::ExistingPublicKeyAddProposal);
            }
        }
        Ok(())
    }

    /// Validate Remove proposals. This function implements the following checks:
    ///  - ValSem107
    ///  - ValSem108
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

            // TODO: ValSem108
            if !self.treesync().is_leaf_in_tree(removed) {
                return Err(ProposalValidationError::UnknownMemberRemoval);
            }
        }

        Ok(())
    }

    /// Validate Update proposals. This function implements the following checks:
    ///  - ValSem109
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    /// TODO: #133 This validation must be updated according to Sec. 13.2
    pub(crate) fn validate_update_proposals(
        &self,
        proposal_queue: &ProposalQueue,
        committer: LeafNodeIndex,
    ) -> Result<HashSet<Vec<u8>>, ProposalValidationError> {
        let mut encryption_keys = HashSet::new();
        for leaf in self.treesync().full_leaves() {
            // 8.3. Leaf Node Validation
            // encryption key must be unique
            encryption_keys.insert(leaf.public_key().as_slice().to_vec());
        }

        // Check the update proposals from the proposal queue first
        let update_proposals = proposal_queue.update_proposals();
        let tree = self.treesync();

        for update_proposal in update_proposals {
            let sender_leaf_index = match update_proposal.sender() {
                Sender::Member(hash_ref) => *hash_ref,
                _ => return Err(ProposalValidationError::UpdateFromNonMember),
            };
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

            if let Some(leaf_node) = tree.leaf(sender_leaf_index) {
                // ValSem109
                // Identity must be unchanged between existing member and new proposal
                if update_proposal
                    .update_proposal()
                    .leaf_node()
                    .credential()
                    .identity()
                    != leaf_node.credential().identity()
                {
                    return Err(ProposalValidationError::UpdateProposalIdentityMismatch);
                }
                let encryption_key = update_proposal
                    .update_proposal()
                    .leaf_node()
                    .encryption_key()
                    .as_slice();
                // ValSem110
                // HPKE init key must be unique among existing members
                if encryption_keys.contains(encryption_key) {
                    return Err(ProposalValidationError::ExistingPublicKeyUpdateProposal);
                }
            } else {
                return Err(ProposalValidationError::UnknownMember);
            }
        }
        Ok(encryption_keys)
    }

    /// Validate the new key package in a path
    /// TODO: #730 - There's nothing testing this function.
    /// - ValSem109
    /// - ValSem110
    pub(super) fn validate_path_key_package(
        &self,
        sender: LeafNodeIndex,
        leaf_node: &LeafNode,
        public_key_set: HashSet<Vec<u8>>,
        proposal_sender: &Sender,
    ) -> Result<(), ProposalValidationError> {
        let mut members = self.treesync().full_leave_members();
        if let Some(Member {
            index: _, identity, ..
        }) = members.find(|Member { index, .. }| index == &sender)
        {
            // ValSem109
            if leaf_node.credential().identity() != identity {
                return Err(ProposalValidationError::UpdateProposalIdentityMismatch);
            }
            // ValSem110
            if public_key_set.contains(leaf_node.encryption_key().as_slice()) {
                return Err(ProposalValidationError::ExistingPublicKeyUpdateProposal);
            }
        } else if proposal_sender.is_member() {
            return Err(ProposalValidationError::UnknownMember);
        }
        Ok(())
    }

    /// Validate constraints on an external commit. This function implements the following checks:
    ///  - ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
    ///  - ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
    ///  - ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
    ///  - ValSem243: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed
    ///               leaf are identical to the ones in the path KeyPackage.
    pub(crate) fn validate_external_commit(
        &self,
        proposal_queue: &ProposalQueue,
        path_leaf_node: Option<&LeafNode>,
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

        let remove_proposals = proposal_queue.filtered_by_type(ProposalType::Remove);
        for proposal in remove_proposals {
            if proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal {
                if let Proposal::Remove(remove_proposal) = proposal.proposal() {
                    let removed_leaf = remove_proposal.removed();

                    if let Some(new_leaf) = path_leaf_node {
                        // ValSem243: External Commit, inline Remove Proposal:
                        //            The identity and the endpoint_id of the
                        //            removed leaf are identical to the ones
                        //            in the path leaf node.
                        let removed_leaf = self
                            .treesync()
                            .leaf(removed_leaf)
                            .ok_or(ExternalCommitValidationError::UnknownMemberRemoval)?;
                        if removed_leaf.credential().identity() != new_leaf.credential().identity()
                        {
                            return Err(ExternalCommitValidationError::InvalidRemoveProposal);
                        }
                    };
                }
            }
        }
        Ok(())
    }
}
