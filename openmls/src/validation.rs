//! # Validation
//!
//! This module implements all validation steps for MLS.
//! 
//! ## Design principle
//! 
//! To ensure that all checks are implemented, a struct needs to ensure that these
//! checks have been performed, BEFORE it is being constructed.

use crate::{
    group::{past_secrets::MessageSecretsStore, PublicGroup, ValidationError},
    prelude::{mls_auth_content_in::VerifiableAuthenticatedContentIn, ProtocolMessage, Sender},
};

type ValidationResult = Result<(), ValidationError>;

/// Application messages MUST always be private messages.
pub(crate) fn application_msg_is_always_private(msg: &ProtocolMessage) -> ValidationResult {
    if msg.is_application_message() && matches!(msg, ProtocolMessage::PublicMessage(_)) {
        return Err(ValidationError::UnencryptedApplicationMessage);
    }

    Ok(())
}

///  A sender must be in the tree.
/// 
/// TODO: This check shouldn't be necessary.
pub(crate) fn sender_is_in_tree(
    group: &PublicGroup,
    verifiable_content: &VerifiableAuthenticatedContentIn,
    message_secrets_store_option: Option<&MessageSecretsStore>,
) -> ValidationResult {
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
        if !group.treesync().is_leaf_in_tree(*leaf_index) && !is_in_secrets_store {
            return Err(ValidationError::UnknownMember);
        }
    }
    Ok(())
}
