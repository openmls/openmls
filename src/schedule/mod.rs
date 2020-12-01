use crate::ciphersuite::*;
use crate::codec::*;
use crate::group::*;
use crate::tree::index::LeafIndex;
use crate::tree::secret_tree::SecretTree;

use self::errors::KeyScheduleError;

pub mod errors;
pub(crate) mod psk;

#[cfg(test)]
mod test_schedule;

pub fn derive_secret(ciphersuite: &Ciphersuite, secret: &Secret, label: &str) -> Secret {
    hkdf_expand_label(ciphersuite, secret, label, &[], ciphersuite.hash_length())
}

pub fn mls_exporter(
    ciphersuite: &Ciphersuite,
    epoch_secrets: &EpochSecrets,
    label: &str,
    group_context: &GroupContext,
    key_length: usize,
) -> Secret {
    let secret = &epoch_secrets.exporter_secret;
    let context = &group_context.serialize();
    let context_hash = &ciphersuite.hash(context);
    hkdf_expand_label(
        ciphersuite,
        &derive_secret(ciphersuite, secret, label),
        "exporter",
        context_hash,
        key_length,
    )
}

pub fn hkdf_expand_label(
    ciphersuite: &Ciphersuite,
    secret: &Secret,
    label: &str,
    context: &[u8],
    length: usize,
) -> Secret {
    let hkdf_label = HkdfLabel::new(context, label, length);
    let info = &hkdf_label.serialize();
    ciphersuite.hkdf_expand(secret, &info, length).unwrap()
}

pub struct HkdfLabel {
    length: u16,
    label: String,
    context: Vec<u8>,
}

impl HkdfLabel {
    pub fn new(context: &[u8], label: &str, length: usize) -> Self {
        let full_label = "mls10 ".to_owned() + label;
        HkdfLabel {
            length: length as u16,
            label: full_label,
            context: context.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        (self.length as u16).encode(&mut buffer).unwrap();
        encode_vec(VecSize::VecU8, &mut buffer, self.label.as_bytes()).unwrap();
        encode_vec(VecSize::VecU32, &mut buffer, &self.context).unwrap();
        buffer
    }
}

#[derive(Clone, Debug)]
pub struct EpochSecrets {
    welcome_secret: Secret,
    sender_data_secret: Secret,
    encryption_secret: Option<Secret>,
    exporter_secret: Secret,
    confirmation_key: Secret,
    init_secret: Secret,
}

impl Default for EpochSecrets {
    fn default() -> Self {
        let welcome_secret = Secret::new_empty_secret();
        let sender_data_secret = Secret::new_empty_secret();
        let encryption_secret = Some(Secret::new_empty_secret());
        let exporter_secret = Secret::new_empty_secret();
        let confirmation_key = Secret::new_empty_secret();
        let init_secret = Secret::new_empty_secret();
        Self {
            welcome_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
}

impl EpochSecrets {
    pub fn get_new_epoch_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        commit_secret: Secret,
        psk: Option<Secret>,
        group_context: &GroupContext,
    ) -> Secret {
        let current_init_secret = self.init_secret.clone();
        let joiner_secret = &ciphersuite.hkdf_extract(&commit_secret, &current_init_secret);
        let welcome_secret = derive_secret(ciphersuite, &joiner_secret, "welcome");
        let pre_member_secret = derive_secret(ciphersuite, &joiner_secret, "member");
        let member_secret = ciphersuite.hkdf_extract(
            &psk.unwrap_or_else(Secret::new_empty_secret),
            &pre_member_secret,
        );
        let pre_epoch_secret = derive_secret(ciphersuite, &member_secret, "epoch");
        let epoch_secret =
            ciphersuite.hkdf_extract(&Secret::from(group_context.serialize()), &pre_epoch_secret);
        let epoch_secrets = Self::derive_epoch_secrets(ciphersuite, &epoch_secret, welcome_secret);
        self.welcome_secret = epoch_secrets.welcome_secret;
        self.sender_data_secret = epoch_secrets.sender_data_secret;
        self.encryption_secret = epoch_secrets.encryption_secret;
        self.exporter_secret = epoch_secrets.exporter_secret;
        self.confirmation_key = epoch_secrets.confirmation_key;
        self.init_secret = epoch_secrets.init_secret;
        epoch_secret
    }

    pub fn derive_epoch_secrets(
        ciphersuite: &Ciphersuite,
        epoch_secret: &Secret,
        welcome_secret: Secret,
    ) -> EpochSecrets {
        let sender_data_secret = derive_secret(ciphersuite, epoch_secret, "sender data");
        let encryption_secret = Some(derive_secret(ciphersuite, epoch_secret, "encryption"));
        let exporter_secret = derive_secret(ciphersuite, epoch_secret, "exporter");
        let confirmation_key = derive_secret(ciphersuite, epoch_secret, "confirm");
        let init_secret = derive_secret(ciphersuite, epoch_secret, "init");
        EpochSecrets {
            welcome_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is replaced with `None` in the
    /// process, allowing us to achieve FS.
    pub fn create_secret_tree(
        &mut self,
        treesize: LeafIndex,
    ) -> Result<SecretTree, KeyScheduleError> {
        let encryption_secret = self.consume_encryption_secret()?;
        Ok(SecretTree::new(encryption_secret, treesize))
    }

    /// Consume the `encryption_secret` from the `EpochSecrets`, replacing it
    /// with `None` and return it.
    fn consume_encryption_secret(&mut self) -> Result<Secret, KeyScheduleError> {
        let encryption_secret = match self.encryption_secret.take() {
            Some(es) => es,
            None => return Err(KeyScheduleError::SecretReuseError),
        };
        Ok(encryption_secret)
    }

    /// Get the sender_data secret.
    pub(crate) fn sender_data_secret(&self) -> &Secret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &Secret {
        &self.confirmation_key
    }
}
