//! This module contains validation functions for incoming messages
//! as defined in <https://github.com/openmls/openmls/wiki/Message-validation>

use std::collections::HashSet;

use crate::{
    framing::Sender,
    group::errors::ExternalCommitValidationError,
    messages::{Proposal, ProposalOrRefType, ProposalType},
};

use super::{
    proposals::ProposalQueue, ContentType, CoreGroup, CoreGroupError, FramingValidationError,
    KeyPackage, MlsMessageIn, ProposalValidationError, VerifiableMlsPlaintext, WireFormat,
};

impl CoreGroup {
    // === Messages ===

    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    pub(crate) fn validate_framing(&self, message: &MlsMessageIn) -> Result<(), CoreGroupError> {
        // ValSem002
        if message.group_id() != self.group_id() {
            return Err(FramingValidationError::WrongGroupId.into());
        }

        // ValSem003: Check boundaries for the epoch
        // We differentiate depending on the content type
        match message.content_type() {
            // For application messages we allow messages for older epochs as well
            ContentType::Application => {
                if message.epoch() > self.context().epoch() {
                    return Err(FramingValidationError::WrongEpoch.into());
                }
            }
            // For all other messages we only only accept the current epoch
            _ => {
                if message.epoch() != self.context().epoch() {
                    return Err(FramingValidationError::WrongEpoch.into());
                }
            }
        }

        Ok(())
    }

    /// Checks the following semantic validation:
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem007
    ///  - ValSem009
    pub(crate) fn validate_plaintext(
        &self,
        plaintext: &VerifiableMlsPlaintext,
    ) -> Result<(), CoreGroupError> {
        // ValSem004
        let sender = plaintext.sender();
        if sender.is_member() {
            if self
                .treesync()
                .leaf_from_id(sender.as_key_package_ref()?)?
                .is_none()
            {
                return Err(FramingValidationError::UnknownMember.into());
            }
        }

        // ValSem005
        // Application messages must always be encrypted
        if plaintext.content_type() == ContentType::Application {
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                return Err(FramingValidationError::UnencryptedApplicationMessage.into());
            } else if !plaintext.sender().is_member() {
                return Err(FramingValidationError::NonMemberApplicationMessage.into());
            }
        }

        // ValSem007
        // If the sender is of type member and the message was not an MlsCiphertext,
        // the member has to prove its ownership by adding a membership tag.
        // The membership tag is checkecked in ValSem008.
        if plaintext.sender().is_member()
            && plaintext.wire_format() != WireFormat::MlsCiphertext
            && plaintext.membership_tag().is_none()
        {
            return Err(FramingValidationError::MissingMembershipTag.into());
        }

        // ValSem009
        if plaintext.content_type() == ContentType::Commit && plaintext.confirmation_tag().is_none()
        {
            return Err(FramingValidationError::MissingConfirmationTag.into());
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
    ///  - ValSem105
    ///  - TODO: ValSem106
    pub(crate) fn validate_add_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), CoreGroupError> {
        let add_proposals = proposal_queue.add_proposals();

        let mut identity_set = HashSet::new();
        let mut signature_key_set = HashSet::new();
        let mut public_key_set = HashSet::new();
        for add_proposal in add_proposals {
            let identity = add_proposal
                .add_proposal()
                .key_package()
                .credential()
                .identity()
                .to_vec();
            // ValSem100
            if !identity_set.insert(identity) {
                return Err(ProposalValidationError::DuplicateIdentityAddProposal.into());
            }
            let signature_key = add_proposal
                .add_proposal()
                .key_package()
                .credential()
                .signature_key()
                .as_slice()
                .to_vec();
            // ValSem101
            if !signature_key_set.insert(signature_key) {
                return Err(ProposalValidationError::DuplicateSignatureKeyAddProposal.into());
            }
            let public_key = add_proposal
                .add_proposal()
                .key_package()
                .hpke_init_key()
                .as_slice()
                .to_vec();
            // ValSem102
            if !public_key_set.insert(public_key) {
                return Err(ProposalValidationError::DuplicatePublicKeyAddProposal.into());
            }
        }

        for (_index, key_package) in self.treesync().full_leaves()? {
            let identity = key_package.credential().identity();
            // ValSem103
            if identity_set.contains(identity) {
                return Err(ProposalValidationError::ExistingIdentityAddProposal.into());
            }
            // ValSem104
            let signature_key = key_package.credential().signature_key().as_slice();
            if signature_key_set.contains(signature_key) {
                return Err(ProposalValidationError::ExistingSignatureKeyAddProposal.into());
            }
            // ValSem105
            let public_key = key_package.hpke_init_key().as_slice();
            if public_key_set.contains(public_key) {
                return Err(ProposalValidationError::ExistingPublicKeyAddProposal.into());
            }
        }
        // TODO #538: ValSem106: Check the required capabilities of the add proposals
        Ok(())
    }

    /// Validate Remove proposals. This function implements the following checks:
    ///  - ValSem107
    ///  - ValSem108
    pub(crate) fn validate_remove_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), CoreGroupError> {
        let remove_proposals = proposal_queue.remove_proposals();

        let mut removes_set = HashSet::new();

        for remove_proposal in remove_proposals {
            let removed = remove_proposal.remove_proposal().removed();
            // ValSem107
            if !removes_set.insert(removed.clone()) {
                return Err(ProposalValidationError::DuplicateMemberRemoval.into());
            }

            // TODO: ValSem108
            if !self.treesync().leaves()?.contains_key(&Some(*removed)) {
                return Err(ProposalValidationError::UnknownMemberRemoval.into());
            }
        }

        Ok(())
    }

    /// Validate Update proposals. This function implements the following checks:
    ///  - ValSem109
    ///  - ValSem110
    pub(crate) fn validate_update_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<HashSet<Vec<u8>>, CoreGroupError> {
        let mut public_key_set = HashSet::new();
        for (_index, key_package) in self.treesync().full_leaves()? {
            let public_key = key_package.hpke_init_key().as_slice().to_vec();
            public_key_set.insert(public_key);
        }

        // Check the update proposals from the proposal queue first
        let update_proposals = proposal_queue.update_proposals();
        let tree = self.treesync();

        for update_proposal in update_proposals {
            if let Some(leaf_node) =
                tree.leaf_from_id(update_proposal.sender().as_key_package_ref()?)?
            {
                let existing_key_package = leaf_node.key_package();
                // ValSem109
                if update_proposal
                    .update_proposal()
                    .key_package()
                    .credential()
                    .identity()
                    != existing_key_package.credential().identity()
                {
                    return Err(ProposalValidationError::UpdateProposalIdentityMismatch.into());
                }
                let public_key = update_proposal
                    .update_proposal()
                    .key_package()
                    .hpke_init_key()
                    .as_slice();
                // ValSem110
                if public_key_set.contains(public_key) {
                    return Err(ProposalValidationError::ExistingPublicKeyUpdateProposal.into());
                }
            } else {
                return Err(ProposalValidationError::UnknownMember.into());
            }
        }
        Ok(public_key_set)
    }

    /// Validate the new key package in a path
    /// TODO: #730 - There's nothing testing this function.
    /// - ValSem109
    /// - ValSem109
    pub(super) fn validate_path_key_package(
        &self,
        sender: u32,
        key_package: &KeyPackage,
        public_key_set: HashSet<Vec<u8>>,
        proposal_sender: &Sender,
    ) -> Result<(), CoreGroupError> {
        let indexed_key_packages = self.treesync().full_leaves()?;
        if let Some(existing_key_package) = indexed_key_packages.get(&sender) {
            // ValSem109
            if key_package.credential().identity() != existing_key_package.credential().identity() {
                return Err(ProposalValidationError::UpdateProposalIdentityMismatch.into());
            }
            // ValSem110
            if public_key_set.contains(key_package.hpke_init_key().as_slice()) {
                return Err(ProposalValidationError::ExistingPublicKeyUpdateProposal.into());
            }
        } else if proposal_sender.is_member() {
            return Err(ProposalValidationError::UnknownMember.into());
        }
        Ok(())
    }

    /// Validate constraints on an external commit. This function implements the following checks:
    ///  - ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
    ///  - ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
    ///  - ValSem242: External Commit, inline Proposals: There MUST NOT be any Add proposals.
    ///  - ValSem243: External Commit, inline Proposals: There MUST NOT be any Update proposals.
    ///  - ValSem244: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed
    ///               leaf are identical to the ones in the path KeyPackage.
    ///  - ValSem245: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
    pub(crate) fn validate_external_commit(
        &self,
        proposal_queue: &ProposalQueue,
        path_key_package_option: Option<&KeyPackage>,
    ) -> Result<(), CoreGroupError> {
        let mut external_init_proposals =
            proposal_queue.filtered_by_type(ProposalType::ExternalInit);
        // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
        if let Some(external_init_proposal) = external_init_proposals.next() {
            // ValSem245: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
            if external_init_proposal.proposal_or_ref_type() == ProposalOrRefType::Reference {
                return Err(ExternalCommitValidationError::ReferencedExternalInitProposal.into());
            }
        } else {
            return Err(ExternalCommitValidationError::NoExternalInitProposals.into());
        };

        // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
        if external_init_proposals.next().is_some() {
            // ValSem245: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
            return Err(ExternalCommitValidationError::MultipleExternalInitProposals.into());
        }

        let add_proposals = proposal_queue.filtered_by_type(ProposalType::Add);
        for proposal in add_proposals {
            // ValSem242: External Commit, inline Proposals: There MUST NOT be any Add proposals.
            if proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal {
                return Err(ExternalCommitValidationError::InvalidInlineProposals.into());
            }
        }
        let update_proposals = proposal_queue.filtered_by_type(ProposalType::Update);
        for proposal in update_proposals {
            // ValSem243: External Commit, inline Proposals: There MUST NOT be any Update proposals.
            if proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal {
                return Err(ExternalCommitValidationError::InvalidInlineProposals.into());
            }
        }

        let remove_proposals = proposal_queue.filtered_by_type(ProposalType::Remove);
        for proposal in remove_proposals {
            if proposal.proposal_or_ref_type() == ProposalOrRefType::Proposal {
                if let Proposal::Remove(remove_proposal) = proposal.proposal() {
                    let removed_leaf = self
                        .treesync()
                        .leaf_from_id(remove_proposal.removed())
                        // Unknown because outside of tree.
                        .map_err(|_| ProposalValidationError::UnknownMemberRemoval)?
                        // Unknown because blank.
                        .ok_or(ProposalValidationError::UnknownMemberRemoval)?;
                    if let Some(path_key_package) = path_key_package_option {
                        // ValSem244: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed leaf are identical to the ones in the path KeyPackage.
                        if removed_leaf.key_package().credential().identity()
                            != path_key_package.credential().identity()
                        {
                            return Err(ExternalCommitValidationError::InvalidRemoveProposal.into());
                        }
                    };
                }
            }
        }
        Ok(())
    }
}
