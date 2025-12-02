//! This module contains validation functions for incoming messages
//! as defined in <https://github.com/openmls/openmls/wiki/Message-validation>

use std::collections::{BTreeSet, HashSet};

use openmls_traits::types::VerifiableCiphersuite;

use super::PublicGroup;
use crate::extensions::RequiredCapabilitiesExtension;
use crate::group::creation::LeafNodeLifetimePolicy;
use crate::group::proposal_store::ProposalQueue;
use crate::group::GroupContextExtensionsProposalValidationError;
use crate::prelude::LibraryError;
use crate::treesync::{errors::LeafNodeValidationError, LeafNode};
use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    framing::{
        mls_auth_content_in::VerifiableAuthenticatedContentIn, ContentType, ProtocolMessage,
        Sender, WireFormat,
    },
    group::{
        errors::{ExternalCommitValidationError, ProposalValidationError, ValidationError},
        past_secrets::MessageSecretsStore,
        Member,
    },
    messages::{
        proposals::{Proposal, ProposalOrRefType, ProposalType},
        Commit,
    },
    schedule::errors::PskError,
};

use crate::treesync::errors::LifetimeError;

#[cfg(feature = "extensions-draft-08")]
use crate::{
    group::errors::AppDataUpdateValidationError, messages::proposals::AppDataUpdateOperationType,
};
#[cfg(feature = "extensions-draft-08")]
use std::collections::BTreeMap;

impl PublicGroup {
    // === Messages ===

    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - [valn1307](https://validation.openmls.tech/#valn1307)
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
                // https://validation.openmls.tech/#valn1307
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
            // old secret tree instance.
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

    /// Validate that all group members support the types of all proposals.
    /// Implements check [valn0311](https://validation.openmls.tech/#valn0311)
    pub(crate) fn validate_proposal_type_support(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        let mut leaves = self.treesync().full_leaves();
        let Some(first_leaf) = leaves.next() else {
            return Ok(());
        };
        // Initialize the capabilities intersection with the capabilities of the
        // first leaf node.
        let mut capabilities_intersection = first_leaf
            .capabilities()
            .proposals()
            .iter()
            .collect::<HashSet<_>>();
        // Iterate over the remaining leaf nodes and intersect their capabilities
        for leaf_node in leaves {
            let leaf_capabilities_set = leaf_node.capabilities().proposals().iter().collect();
            capabilities_intersection = capabilities_intersection
                .intersection(&leaf_capabilities_set)
                .cloned()
                .collect();
        }

        // Check that the types of all non-default proposals are supported by all members
        for proposal in proposal_queue.queued_proposals() {
            let proposal_type = proposal.proposal().proposal_type();
            if !proposal_type.is_default() && !capabilities_intersection.contains(&proposal_type) {
                return Err(ProposalValidationError::UnsupportedProposalType);
            }
        }
        Ok(())
    }

    /// Validate key uniqueness. This function implements the following checks:
    ///  - ValSem101: Add Proposal: Signature public key in proposals must be unique among proposals & members
    ///  - ValSem102: Add Proposal: Init key in proposals must be unique among proposals
    ///  - ValSem103: Add Proposal: Encryption key in proposals must be unique among proposals & members
    ///  - ValSem104: Add Proposal: Init key and encryption key must be different
    ///  - ValSem110: Update Proposal: Encryption key must be unique among proposals & members
    ///  - ValSem206: Commit: Path leaf node encryption key must be unique among proposals & members
    ///  - ValSem207: Commit: Path encryption keys must be unique among proposals & members
    ///  - [valn0111]: Verify that the following fields are unique among the members of the group: `signature_key`
    ///  - [valn0112]: Verify that the following fields are unique among the members of the group: `encryption_key`
    ///
    /// [valn0111]: https://validation.openmls.tech/#valn0111
    /// [valn0112]: https://validation.openmls.tech/#valn0112
    /// [valn1208]: https://validation.openmls.tech/#valn1208
    pub(crate) fn validate_key_uniqueness(
        &self,
        proposal_queue: &ProposalQueue,
        commit: Option<&Commit>,
    ) -> Result<(), ProposalValidationError> {
        let mut signature_key_set = HashSet::new();
        let mut init_key_set = HashSet::new();
        let mut encryption_key_set = HashSet::new();

        // Handle the exceptions needed for https://validation.openmls.tech/#valn0306
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
        //  - https://validation.openmls.tech/#valn0111
        //  - https://validation.openmls.tech/#valn0305
        //  - https://validation.openmls.tech/#valn0306
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
        //  - https://validation.openmls.tech/#valn0112
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

    /// Validate capabilities. This function implements the following checks:
    /// - ValSem106: Add Proposal: required capabilities
    /// - ValSem109: Update Proposal: required capabilities
    /// - [valn0113](https://validation.openmls.tech/#valn0113).
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
        //   type (https://validation.openmls.tech/#valn0113).
        // - Check that the credential type is supported by all members of the
        //   group.
        // - Check that the capabilities field of this LeafNode indicates
        //   support for all the credential types currently in use by other
        //   members.

        // Extract the leaf nodes from the add & update proposals and validate them
        proposal_queue
            .queued_proposals()
            .filter_map(|p| match p.proposal() {
                Proposal::Add(add_proposal) => Some(add_proposal.key_package().leaf_node()),
                Proposal::Update(update_proposal) => Some(update_proposal.leaf_node()),
                _ => None,
            })
            .try_for_each(|leaf_node| {
                self.validate_leaf_node_capabilities(leaf_node)
                    .map_err(|_| ProposalValidationError::InsufficientCapabilities)
            })
    }

    /// Validate Add proposals. This function implements the following checks:
    ///  - ValSem105: Add Proposal: Ciphersuite & protocol version must match the group
    pub(crate) fn validate_add_proposals(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ProposalValidationError> {
        let add_proposals = proposal_queue.add_proposals();

        // We do the key package validation checks here inline
        // https://validation.openmls.tech/#valn0501
        for add_proposal in add_proposals {
            // ValSem105: Check if ciphersuite and version of the group are correct:
            // https://validation.openmls.tech/#valn0201
            if add_proposal.add_proposal().key_package().ciphersuite() != self.ciphersuite()
                || add_proposal.add_proposal().key_package().protocol_version() != self.version()
            {
                return Err(ProposalValidationError::InvalidAddProposalCiphersuiteOrVersion);
            }

            // https://validation.openmls.tech/#valn0202
            self.validate_leaf_node(add_proposal.add_proposal().key_package().leaf_node())?;
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
        let updates_set: HashSet<_> = proposal_queue
            .update_proposals()
            .map(|proposal| {
                if let Sender::Member(index) = proposal.sender() {
                    Ok(*index)
                } else {
                    Err(ProposalValidationError::UpdateFromNonMember)
                }
            })
            .collect::<Result<_, _>>()?;

        let remove_proposals = proposal_queue.remove_proposals();

        let mut removes_set = HashSet::new();

        // https://validation.openmls.tech/#valn0701
        for remove_proposal in remove_proposals {
            let removed = remove_proposal.remove_proposal().removed();
            // The node has to be a leaf in the tree
            // ValSem108
            if !self.treesync().is_leaf_in_tree(removed) {
                return Err(ProposalValidationError::UnknownMemberRemoval);
            }

            // ValSem107
            // https://validation.openmls.tech/#valn0304
            if !removes_set.insert(removed) {
                return Err(ProposalValidationError::DuplicateMemberRemoval);
            }
            if updates_set.contains(&removed) {
                return Err(ProposalValidationError::DuplicateMemberRemoval);
            }

            // removed node can not be blank
            if self.treesync().leaf(removed).is_none() {
                return Err(ProposalValidationError::UnknownMemberRemoval);
            }
        }

        Ok(())
    }

    /// Validate Update proposals. This function implements the following checks:
    ///  - ValSem111: Update Proposal: The sender of a full Commit must not include own update proposals
    ///  - ValSem112: Update Proposal: The sender of a standalone update proposal must be of type member
    ///
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

            // https://validation.openmls.tech/#valn0601
            self.validate_leaf_node(update_proposal.update_proposal().leaf_node())?;
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
            // https://validation.openmls.tech/#valn0803
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
    pub(crate) fn validate_external_commit(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), ExternalCommitValidationError> {
        // [valn0401](https://validation.openmls.tech/#valn0401)
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
        // [valn0404](https://validation.openmls.tech/#valn0404)
        let contains_denied_proposal = proposal_queue.queued_proposals().any(|p| {
            let is_inline = p.proposal_or_ref_type() == ProposalOrRefType::Proposal;
            let is_allowed_type = matches!(
                p.proposal(),
                Proposal::ExternalInit(_)
                    | Proposal::Remove(_)
                    | Proposal::PreSharedKey(_)
                    | Proposal::Custom(_)
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
    /// Implements check [valn1001](https://validation.openmls.tech/#valn1001).
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
                    // that they are default extensions or included in the required capabilities.
                    let all_extensions_are_in_required_capabilities: bool = extensions
                        .extensions()
                        .iter()
                        .map(|ext| ext.extension_type())
                        .all(|ext_type| {
                            ext_type.is_default()
                                || required_capabilities.requires_extension_type_support(ext_type)
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
    #[cfg(feature = "extensions-draft-08")]
    /// Returns an [`AppDataUpdateValidationError`] if:
    ///   - An [`AppDataUpdateProposal`] appears before a [`GroupContextExtensionProposal`]
    ///   - The [`GroupContextExtensionProposal`] updates the [`AppDataDictionary`] when the
    ///     required capabilities include AppDataUpdate proposal type
    ///   - For any [`ComponentId`], the list of [`AppDataUpdateProposal`]s includes both Updates
    ///   and Removes
    ///   - For any [`ComponentId`], the list of [`AppDataUpdateProposal`]s includes more than one
    ///   Remove
    pub(crate) fn validate_app_data_update_proposals_and_group_context(
        &self,
        proposal_queue: &ProposalQueue,
    ) -> Result<(), AppDataUpdateValidationError> {
        let no_app_data_updates = proposal_queue.app_data_update_proposals().next().is_none();
        if no_app_data_updates {
            return Ok(());
        }
        // retrieve the GroupContextExtensions proposal, if available
        let group_context_extension = proposal_queue
            .filtered_by_type(ProposalType::GroupContextExtensions)
            .filter_map(|queued_proposal| match queued_proposal.proposal() {
                Proposal::GroupContextExtensions(p) => Some(p),
                _ => None,
            })
            .next();

        // check ordering
        // return an error if an AppDataUpdate appears before a GroupContextExtensions proposal
        if proposal_queue
            .queued_proposals()
            .map(|proposal| proposal.proposal().proposal_type())
            .skip_while(|proposal_type| *proposal_type != ProposalType::AppDataUpdate)
            .any(|proposal_type| proposal_type == ProposalType::GroupContextExtensions)
        {
            return Err(AppDataUpdateValidationError::IncorrectOrder);
        }

        // FIXME(keks): I believe this whole check is wrong. I think we need to
        // 1. check that this is supported by everyone before using it
        // 2. if appdataupdate is in required_capabilities, then do not allow using the old way of
        //    updating a group context extension to change the app data dict.
        //   validate that GroupContextExtensions does not update the AppDataDictionary using
        //   GroupContextExtensions. However, posting such an extensions with the current state is
        //   fine
        //   https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.7-6
        //   What the doc doesn't make entirely clear I think is what if we have both appdataupdate
        //   and gce, and the gce contains the full state after the diff was applied (for compat).
        //   is that legal?
        //   Sort of encoded in
        //   https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.7-7
        //   but not explicitly
        if let Some(group_context_extension) = group_context_extension {
            let extensions = group_context_extension.extensions();

            if let Some(required_capabilities) = extensions.required_capabilities() {
                // TODO: should it also be ensured here that the AppDataDictionary extension type is
                // supported?
                if required_capabilities
                    .proposal_types()
                    .contains(&ProposalType::AppDataUpdate)
                {
                    // if the app data dictionary is not updated, this is valid
                    if extensions.app_data_dictionary()
                        != self.group_context().extensions().app_data_dictionary()
                    {
                        return Err(AppDataUpdateValidationError::CannotUpdateDictionaryDirectly);
                    }
                }
            }
        }

        // get the app data update proposals
        let app_data_update_proposals = proposal_queue
            .filtered_by_type(ProposalType::AppDataUpdate)
            .filter_map(|queued_proposal| match queued_proposal.proposal() {
                Proposal::AppDataUpdate(p) => Some(p),
                _ => None,
            });

        // validate that proposals for each component are either:
        //   - A: one or more updates, or
        //   - B: exactly one remove
        let mut operation_type_per_component_id = BTreeMap::new();
        for proposal in app_data_update_proposals {
            let component_id = proposal.component_id();
            let operation_type = proposal.operation().operation_type();

            match operation_type_per_component_id.get(&component_id) {
                // mismatched types
                Some(already_seen) if *already_seen != operation_type => {
                    return Err(AppDataUpdateValidationError::CombinedRemoveAndUpdateOperations);
                }
                // only one remove allowed
                Some(&AppDataUpdateOperationType::Remove) => {
                    return Err(AppDataUpdateValidationError::MoreThanOneRemovePerComponentId)
                }
                // more updates allowed
                Some(&AppDataUpdateOperationType::Update) => {}
                None => {
                    let _ = operation_type_per_component_id.insert(component_id, operation_type);
                }
            }
        }

        Ok(())
    }

    fn validate_leaf_node_capabilities(
        &self,
        leaf_node: &LeafNode,
    ) -> Result<(), LeafNodeValidationError> {
        // Check that the data in the leaf node is self-consistent
        // Check that the capabilities contain the leaf node's credential
        // type (https://validation.openmls.tech/#valn0113)
        // Check that all extension types are valid in leaf node
        // (https://validation.openmls.tech/#valn1601)
        leaf_node.validate_locally()?;

        // Check if the ciphersuite and the version of the group are
        // supported.
        let capabilities = leaf_node.capabilities();
        if !capabilities.contains_ciphersuite(VerifiableCiphersuite::from(self.ciphersuite()))
            || !capabilities.contains_version(self.version())
        {
            return Err(LeafNodeValidationError::CiphersuiteNotInCapabilities);
        }

        // If there is a required capabilities extension, check if that one
        // is supported (https://validation.openmls.tech/#valn0103).
        if let Some(required_capabilities) =
            self.group_context().extensions().required_capabilities()
        {
            // Check if all required capabilities are supported.
            capabilities.supports_required_capabilities(required_capabilities)?;
        }

        // Check that the credential type is supported by all members of the group (https://validation.openmls.tech/#valn0104).
        if !self.treesync().full_leaves().all(|node| {
            node.capabilities()
                .contains_credential(leaf_node.credential().credential_type())
        }) {
            return Err(LeafNodeValidationError::UnsupportedCredentials);
        }

        // Check that the capabilities field of this LeafNode indicates
        // support for all the credential types currently in use by other
        // members (https://validation.openmls.tech/#valn0104).
        if !self
            .treesync()
            .full_leaves()
            .all(|node| capabilities.contains_credential(node.credential().credential_type()))
        {
            return Err(LeafNodeValidationError::UnsupportedCredentials);
        }

        Ok(())
    }

    /// Validate a leaf node.
    ///
    /// This always validates the lifetime.
    pub(crate) fn validate_leaf_node(
        &self,
        leaf_node: &crate::treesync::LeafNode,
    ) -> Result<(), LeafNodeValidationError> {
        // Call the validation function and validate the lifetime
        self.validate_leaf_node_inner(leaf_node, LeafNodeLifetimePolicy::Verify)
    }

    /// Validate a leaf node.
    ///
    /// This may skip checking the lifetime when validating a ratchet tree.
    pub(crate) fn validate_leaf_node_inner(
        &self,
        leaf_node: &crate::treesync::LeafNode,
        validate_lifetimes: LeafNodeLifetimePolicy,
    ) -> Result<(), LeafNodeValidationError> {
        // https://validation.openmls.tech/#valn0103
        // https://validation.openmls.tech/#valn0104
        // https://validation.openmls.tech/#valn0107
        self.validate_leaf_node_capabilities(leaf_node)?;

        // https://validation.openmls.tech/#valn0105 is done when sending

        // https://validation.openmls.tech/#valn0106
        //
        // Only leaf nodes in key packages contain lifetimes, so this will return None for other
        // cases. Therefore we only check the lifetimes for leaf nodes in key packages.
        //
        // We may want to check these in ratchet trees as well.
        // However, this may lead to errors when leaf nodes don't get updated
        // after being added to the tree. RFC 9420 recommends checking the lifetime
        // but acknowledges already that this may cause issues.
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3-4.5.1
        // See #1810 for more background.
        // We therefore check the lifetime by default, but skip it if ...
        //
        // Some KATs use key packages that are expired by now. In order to run these tests, we
        // provide a way to turn off this check.
        if matches!(validate_lifetimes, LeafNodeLifetimePolicy::Verify)
            && !crate::skip_validation::is_disabled::leaf_node_lifetime()
        {
            if let Some(lifetime) = leaf_node.life_time() {
                if !lifetime.is_valid() {
                    log::warn!(
                        "offending lifetime: {lifetime:?} for leaf node with {credential:?}",
                        credential = leaf_node.credential()
                    );
                    return Err(LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent));
                }
            }
        }

        // These are done at the caller and we can't do them here:
        //
        // https://validation.openmls.tech/#valn0108
        // https://validation.openmls.tech/#valn0109
        // https://validation.openmls.tech/#valn0110

        // These are done in validate_key_uniqueness, which is called in the context of changing
        // this group:
        //
        // https://validation.openmls.tech/#valn0111
        // https://validation.openmls.tech/#valn0112

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
