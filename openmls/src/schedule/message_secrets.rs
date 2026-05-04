//! This module defines the [`MessageSecrets`] struct that can be used for message decryption & verification

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use super::*;

/// Combined message secrets that need to be stored for later decryption/verification
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecrets {
    sender_data_secret: SenderDataSecret,
    membership_key: MembershipKey,
    confirmation_key: ConfirmationKey,
    serialized_context: Vec<u8>,
    secret_tree: SecretTree,
    /// When the secrets were added to the store
    /// `None` if no timestamp is available
    /// NOTE: SystemTime is not guaranteed to be monotonic.
    #[serde(default)]
    added_at: Option<SystemTime>,
}

#[cfg(not(feature = "crypto-debug"))]
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

// Public functions
impl MessageSecrets {
    ///Create new `MessageSecrets`
    pub(crate) fn new(
        sender_data_secret: SenderDataSecret,
        membership_key: MembershipKey,
        confirmation_key: ConfirmationKey,
        serialized_context: Vec<u8>,
        secret_tree: SecretTree,
    ) -> Self {
        Self {
            sender_data_secret,
            membership_key,
            confirmation_key,
            serialized_context,
            secret_tree,
            added_at: None,
        }
    }

    /// Get a reference to the message secrets's sender data secret.
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get a reference to the message secrets's membership key.
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// Get a reference to the message secrets's confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Get a reference to the message secrets's serialized context.
    pub(crate) fn serialized_context(&self) -> &[u8] {
        self.serialized_context.as_ref()
    }

    /// Get a mutable reference to the message secrets's secret tree.
    pub(crate) fn secret_tree_mut(&mut self) -> &mut SecretTree {
        &mut self.secret_tree
    }

    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.added_at
    }

    pub(crate) fn with_timestamp(self, timestamp: impl Into<Option<SystemTime>>) -> Self {
        Self {
            added_at: timestamp.into(),
            ..self
        }
    }

    /// Helper function to create a `MessageSecrets` with `None` timestamp
    #[cfg(test)]
    pub(crate) fn without_timestamp(self) -> Self {
        Self {
            added_at: None,
            ..self
        }
    }
}

// Test functions
impl MessageSecrets {
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }

    #[cfg(test)]
    /// Update the message secrets's serialized context.
    pub(crate) fn set_serialized_context(&mut self, serialized_context: Vec<u8>) {
        self.serialized_context = serialized_context;
    }

    #[cfg(test)]
    /// Update the membership key.
    pub(crate) fn set_membership_key(&mut self, membership_key: Secret) {
        self.membership_key = MembershipKey::from_secret(membership_key);
    }

    #[cfg(test)]
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rng: &impl OpenMlsRand,
        own_index: LeafNodeIndex,
    ) -> Self {
        Self {
            sender_data_secret: SenderDataSecret::random(ciphersuite, rng),
            membership_key: MembershipKey::random(ciphersuite, rng),
            confirmation_key: ConfirmationKey::random(ciphersuite, rng),
            serialized_context: rng.random_vec(10).expect("Not enough randomness."),
            secret_tree: SecretTree::new(
                EncryptionSecret::random(ciphersuite, rng),
                TreeSize::new(10),
                own_index,
            ),
            added_at: None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn replace_secret_tree(&mut self, secret_tree: SecretTree) -> SecretTree {
        std::mem::replace(&mut self.secret_tree, secret_tree)
    }
}

// In tests we allow comparing secrets.
#[cfg(any(test, feature = "test-utils"))]
impl PartialEq for MessageSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.membership_key == other.membership_key
            && self.confirmation_key == other.confirmation_key
            && self.secret_tree == other.secret_tree
    }
}
