//! This module defines the [`MessageSecrets`] struct that can be used for message decryption & verification

use super::*;
#[cfg(test)]
use crate::tree::index::LeafIndex;
/// Combined message secrets that need to be stored for later decryption/verification
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageSecrets {
    sender_data_secret: SenderDataSecret,
    membership_key: MembershipKey,
    confirmation_key: ConfirmationKey,
    serialized_context: Vec<u8>,
    pub(crate) secret_tree: SecretTree,
}

// Public functions
impl MessageSecrets {
    ///Create new `MessageSecrets`
    pub fn new(
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
        }
    }

    /// Get a reference to the message secrets's sender data secret.
    pub fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get a reference to the message secrets's membership key.
    pub fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// Get a reference to the message secrets's confirmation key.
    pub fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Get a reference to the message secrets's serialized context.
    pub fn serialized_context(&self) -> &[u8] {
        self.serialized_context.as_ref()
    }

    /// Get a reference to the message secrets's secret tree.
    pub fn secret_tree(&self) -> &SecretTree {
        &self.secret_tree
    }

    /// Get a mutable reference to the message secrets's secret tree.
    pub fn secret_tree_mut(&mut self) -> &mut SecretTree {
        &mut self.secret_tree
    }
}

// Test functions
impl MessageSecrets {
    #[cfg(any(feature = "test-utils", test))]
    pub fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }

    #[cfg(test)]
    pub fn random(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) -> Self {
        use openmls_traits::random::OpenMlsRand;

        Self {
            sender_data_secret: SenderDataSecret::random(ciphersuite, backend),
            membership_key: MembershipKey::random(ciphersuite, backend),
            confirmation_key: ConfirmationKey::random(ciphersuite, backend),
            serialized_context: backend
                .rand()
                .random_vec(10)
                .expect("Not enough randomness."),
            secret_tree: SecretTree::new(
                EncryptionSecret::random(ciphersuite, backend),
                LeafIndex(10),
            ),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn replace_secret_tree(&mut self, secret_tree: SecretTree) -> SecretTree {
        std::mem::replace(&mut self.secret_tree, secret_tree)
    }
}

// In tests we allow comparing secrets.
#[cfg(test)]
impl PartialEq for MessageSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.membership_key == other.membership_key
            && self.confirmation_key == other.confirmation_key
    }
}
