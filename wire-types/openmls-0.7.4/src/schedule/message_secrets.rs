//! This module defines the [`MessageSecrets`] struct that can be used for message decryption & verification

use super::*;

/// Combined message secrets that need to be stored for later decryption/verification
#[derive(Serialize, Deserialize)]
pub(crate) struct MessageSecrets {
    sender_data_secret: SenderDataSecret,
    membership_key: MembershipKey,
    confirmation_key: ConfirmationKey,
    serialized_context: Vec<u8>,
    secret_tree: SecretTree,
}

impl core::fmt::Debug for MessageSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecrets")
            .field("sender_data_secret", &"***")
            .field("membership_key", &"***")
            .field("confirmation_key", &"***")
            .field("serialized_context", &"***")
            .field("secret_tree", &"***")
            .finish()
    }
}
