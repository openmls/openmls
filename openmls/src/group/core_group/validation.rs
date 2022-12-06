//! This module contains validation functions for incoming messages
//! as defined in <https://github.com/openmls/openmls/wiki/Message-validation>

use std::collections::HashSet;

use crate::{
    error::LibraryError,
    extensions::ExtensionType,
    framing::Sender,
    group::errors::ExternalCommitValidationError,
    group::errors::ValidationError,
    messages::proposals::{Proposal, ProposalOrRefType, ProposalType},
};

use super::{
    proposals::ProposalQueue, ContentType, CoreGroup, KeyPackage, Member, MlsMessageIn,
    ProposalValidationError, VerifiableMlsAuthContent, WireFormat,
};

impl CoreGroup {
    // === Messages ===

    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    pub(crate) fn validate_framing(&self, message: &MlsMessageIn) -> Result<(), ValidationError> {
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
    pub(crate) fn validate_plaintext(
        &self,
        plaintext: &VerifiableMlsAuthContent,
    ) -> Result<(), ValidationError> {
        // ValSem004
        let sender = plaintext.sender();
        if let Sender::Member(leaf_index) = sender {
            // If the sender is a member, it has to be in the tree.
            // TODO: #133 Lookup of a leaf index in the old tree isn't very
            //       useful. Add a proper validation step here.
            if self.treesync().leaf_is_in_tree(*leaf_index).is_err()
                && !self
                    .message_secrets_store
                    .epoch_has_leaf(plaintext.epoch(), *leaf_index)
            {
                return Err(ValidationError::UnknownMember);
            }
        }

        // ValSem005
        // Application messages must always be encrypted
        if plaintext.content_type() == ContentType::Application {
            if plaintext.wire_format() != WireFormat::MlsCiphertext {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !plaintext.sender().is_member() {
                return Err(ValidationError::NonMemberApplicationMessage);
            }
        }

        // ValSem009
        if plaintext.content_type() == ContentType::Commit && plaintext.confirmation_tag().is_none()
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
    ///  - ValSem105
    ///  - ValSem106
    pub(crate) fn validate_add_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
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
                return Err(ProposalValidationError::DuplicateIdentityAddProposal);
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
                return Err(ProposalValidationError::DuplicateSignatureKeyAddProposal);
            }
            let public_key = add_proposal
                .add_proposal()
                .key_package()
                .hpke_init_key()
                .as_slice()
                .to_vec();
            // ValSem102
            if !public_key_set.insert(public_key) {
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
                .extension_with_type(ExtensionType::Capabilities)
                .ok_or(ProposalValidationError::InsufficientCapabilities)?
                .as_capabilities_extension()
                .map_err(|_| {
                    // Mismatches between Extensions and ExtensionTypes should be
                    // caught when constructing KeyPackages.
                    ProposalValidationError::LibraryError(LibraryError::custom(
                        "ExtensionType didn't match extension content.",
                    ))
                })?;
            if !capabilities.ciphersuites().contains(&self.ciphersuite())
                || !capabilities.versions().contains(&self.version())
            {
                log::error!("Tried to commit an Add proposal, where either the group's `Ciphersuite` or the group's `ProtocolVersion` is not in the `KeyPackage`'s `Capabilities`.");
                return Err(ProposalValidationError::InsufficientCapabilities);
            }
            // If there is a required capabilities extension, check if that one
            // is supported.
            if let Some(required_capabilities_extension) = self
                .group_context_extensions()
                .iter()
                .find(|&e| e.extension_type() == ExtensionType::RequiredCapabilities)
            {
                let required_capabilities = required_capabilities_extension
                    .as_required_capabilities_extension()
                    .map_err(|_| {
                        // Mismatches between Extensions and ExtensionTypes should be
                        // caught when constructing KeyPackages.
                        ProposalValidationError::LibraryError(LibraryError::custom(
                            "ExtensionType didn't match extension content.",
                        ))
                    })?;
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
            encryption_key: _,
            signature_key,
        } in self.treesync().full_leave_members()?
        {
            // ValSem103
            if identity_set.contains(&identity) {
                return Err(ProposalValidationError::ExistingIdentityAddProposal);
            }
            // ValSem104
            if signature_key_set.contains(&signature_key) {
                return Err(ProposalValidationError::ExistingSignatureKeyAddProposal);
            }
            // ValSem105
            let public_key = self
                .treesync()
                .leaf(index)
                .map_err(|_| ProposalValidationError::UnknownMember)?
                .ok_or(ProposalValidationError::UnknownMember)?
                .public_key()
                .as_slice();
            if public_key_set.contains(public_key) {
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
            if self.treesync().leaf_is_in_tree(removed).is_err() {
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
        committer: u32,
    ) -> Result<HashSet<Vec<u8>>, ProposalValidationError> {
        let mut encryption_keys = HashSet::new();
        for index in self.treesync().full_leaves()? {
            // 8.3. Leaf Node Validation
            // encryption key must be unique
            encryption_keys.insert(
                self.treesync()
                    .leaf(index)
                    .and_then(|leaf| {
                        leaf.map(|leaf| leaf.public_key()).ok_or_else(|| {
                            LibraryError::custom("This must have been a leaf node").into()
                        })
                    })
                    .map_err(|_| LibraryError::custom("This must have been a leaf node."))?
                    .as_slice()
                    .to_vec(),
            );
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

            if let Some(leaf_node) = tree
                .leaf(sender_leaf_index)
                .map_err(|_| ProposalValidationError::UnknownMember)?
            {
                let existing_key_package = leaf_node.key_package();
                // ValSem109
                // Identity must be unchanged between existing member and new proposal
                if update_proposal
                    .update_proposal()
                    .key_package()
                    .credential()
                    .identity()
                    != existing_key_package.credential().identity()
                {
                    return Err(ProposalValidationError::UpdateProposalIdentityMismatch);
                }
                // FIXME: #819 The update proposal will hold the leaf.
                let encryption_key = update_proposal
                    .update_proposal()
                    .key_package()
                    .hpke_init_key()
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
        sender: u32,
        key_package: &KeyPackage,
        public_key_set: HashSet<Vec<u8>>,
        proposal_sender: &Sender,
    ) -> Result<(), ProposalValidationError> {
        let members = self.treesync().full_leave_members()?;
        if let Some(Member {
            index: _, identity, ..
        }) = members.iter().find(|Member { index, .. }| index == &sender)
        {
            // ValSem109
            if key_package.credential().identity() != identity {
                return Err(ProposalValidationError::UpdateProposalIdentityMismatch);
            }
            // ValSem110
            if public_key_set.contains(key_package.hpke_init_key().as_slice()) {
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
    ///  - ValSem244: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
    pub(crate) fn validate_external_commit(
        &self,
        proposal_queue: &ProposalQueue,
        path_key_package_option: Option<&KeyPackage>,
    ) -> Result<(), ExternalCommitValidationError> {
        let mut external_init_proposals =
            proposal_queue.filtered_by_type(ProposalType::ExternalInit);
        // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
        if let Some(external_init_proposal) = external_init_proposals.next() {
            // ValSem244: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
            if external_init_proposal.proposal_or_ref_type() == ProposalOrRefType::Reference {
                return Err(ExternalCommitValidationError::ReferencedExternalInitProposal);
            }
        } else {
            return Err(ExternalCommitValidationError::NoExternalInitProposals);
        };

        // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
        if external_init_proposals.next().is_some() {
            // ValSem244: External Commit, referenced Proposals: There MUST NOT be any ExternalInit proposals.
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

                    if let Some(path_key_package) = path_key_package_option {
                        // ValSem243: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed leaf are identical to the ones in the path KeyPackage.
                        let leaf = self
                            .treesync()
                            .leaf(removed_leaf)
                            .map_err(|_| ExternalCommitValidationError::UnknownMemberRemoval)?
                            .ok_or(ExternalCommitValidationError::UnknownMemberRemoval)?;
                        if leaf.key_package().credential().identity()
                            != path_key_package.credential().identity()
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
