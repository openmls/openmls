use crate::ciphersuite::*;
use crate::codec::*;
use crate::group::*;
use crate::messages::{proposals::AddProposal, GroupSecrets, PathSecret};
use crate::tree::index::LeafIndex;
use crate::tree::index::NodeIndex;
use crate::tree::private_tree::CommitSecret;
use crate::tree::secret_tree::SecretTree;
use crate::tree::treemath;
use crate::tree::RatchetTree;

use self::errors::KeyScheduleError;

pub mod errors;

pub fn derive_secret(ciphersuite: &Ciphersuite, secret: &Secret, label: &str) -> Secret {
    hkdf_expand_label(ciphersuite, secret, label, &[], ciphersuite.hash_length())
}

/// The `InitSecret` is used to start the connect the next epoch to the current
/// one. It's necessary to be able clone this to create a provisional group
/// state, which includes the `InitSecret`.
#[derive(Debug, Clone)]
pub struct InitSecret {
    secret: Secret,
}

impl InitSecret {
    /// Derive an `InitSecret` from an `EpochSecret`.
    fn derive_init_secret(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        InitSecret {
            secret: derive_secret(ciphersuite, &epoch_secret.secret, "init"),
        }
    }

    /// Sample a fresh, random `InitiSecret` for the creation of a new group.
    pub(crate) fn from_random(length: usize) -> Self {
        InitSecret {
            secret: Secret::from_random(length),
        }
    }
}

/// It's necessary to clone this to be able generate `GroupSecret` object with
/// multiple different `PathSecret` objects.
#[derive(Debug, Clone)]
pub struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from a `CommitSecret` and an `EpochSecrets`
    /// object, which onctains the necessary `InitSecret`. TODO: For now, this
    /// takes a reference to a `CommitSecret` as input. This should change with
    /// #224.
    pub(crate) fn derive_joiner_secret(
        ciphersuite: &Ciphersuite,
        commit_secret: &CommitSecret,
        init_secret: InitSecret,
    ) -> Self {
        JoinerSecret {
            secret: ciphersuite.hkdf_extract(commit_secret.secret(), &init_secret.secret),
        }
    }

    /// Derive the inital `JoinerSecret` when creating a new group from a
    /// `CommitSecret`. The `InitSecret` is randomly generated. TODO:
    /// For now, this takes a reference to a `CommitSecret` as input. This
    /// should change with #224.
    fn derive_initial_joiner_secret(
        ciphersuite: &Ciphersuite,
        commit_secret: &CommitSecret,
    ) -> Self {
        let initial_init_secret = InitSecret::from_random(ciphersuite.hash_length());
        JoinerSecret {
            secret: ciphersuite.hkdf_extract(commit_secret.secret(), &initial_init_secret.secret),
        }
    }

    /// Create the `GroupSecrets` for a number of `invited_members` based on a
    /// provisional `RatchetTree`. `path_required` indicates if we need to
    /// include a `path_secret` into the `GroupSecrets`.
    pub(crate) fn create_group_secrets(
        &self,
        invited_members: &Vec<(NodeIndex, AddProposal)>,
        ciphersuite: &Ciphersuite,
        path_required: bool,
        provisional_tree: &RatchetTree,
        path_secrets_option: Option<Vec<Secret>>,
    ) -> Vec<(HPKEPublicKey, Vec<u8>, Vec<u8>)> {
        let mut plaintext_secrets = vec![];
        for (index, add_proposal) in invited_members.clone() {
            let key_package = add_proposal.key_package;
            let key_package_hash = ciphersuite.hash(&key_package.encode_detached().unwrap());
            let path_secret = if path_required {
                let common_ancestor_index =
                    treemath::common_ancestor_index(index, provisional_tree.get_own_node_index());
                let dirpath = treemath::direct_path_root(
                    provisional_tree.get_own_node_index(),
                    provisional_tree.leaf_count(),
                )
                .expect("create_commit_internal: TreeMath error when computing direct path.");
                let position = dirpath
                    .iter()
                    .position(|&x| x == common_ancestor_index)
                    .unwrap();
                let path_secrets = path_secrets_option.clone().unwrap();
                let path_secret = path_secrets[position].clone();
                Some(PathSecret { path_secret })
            } else {
                None
            };
            let group_secrets = GroupSecrets {
                joiner_secret: self.clone(),
                path_secret,
            };
            let group_secrets_bytes = group_secrets.encode_detached().unwrap();
            plaintext_secrets.push((
                key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
            ));
        }
        plaintext_secrets
    }
}

impl Codec for JoinerSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.secret.encode(buffer)
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret = Secret::decode(cursor)?;
        Ok(JoinerSecret { secret })
    }
}

pub struct MemberSecret {
    secret: Secret,
}

impl MemberSecret {
    /// Derive a `MemberSecret` from a `CommitSecret` and a `JoinerSecret`
    /// object. This doesn't consume the `JoinerSecret` object, because we need
    /// it later in the `create_commit` function to create `GroupSecret`
    /// objects. TODO: The PSK should get its own dedicated type in the process
    /// of tackling issue #141.
    pub(crate) fn derive_member_secret(
        ciphersuite: &Ciphersuite,
        joiner_secret: &JoinerSecret,
        psk: Option<Secret>,
    ) -> Self {
        let intermediate_secret = derive_secret(ciphersuite, &joiner_secret.secret, "member");
        MemberSecret {
            secret: ciphersuite.hkdf_extract(
                &psk.unwrap_or_else(Secret::new_empty_secret),
                &intermediate_secret,
            ),
        }
    }

    /// Derive an initial `MemberSecret` when creating a new group. TODO: The
    /// PSK should get its own dedicated type in the process of tackling issue
    /// #141.
    pub(crate) fn derive_initial_member_secret(
        ciphersuite: &Ciphersuite,
        commit_secret: &CommitSecret,
        psk: Option<Secret>,
    ) -> Self {
        let joiner_secret = JoinerSecret::derive_initial_joiner_secret(ciphersuite, commit_secret);
        let intermediate_secret = derive_secret(ciphersuite, &joiner_secret.secret, "member");
        MemberSecret {
            secret: ciphersuite.hkdf_extract(
                &psk.unwrap_or_else(Secret::new_empty_secret),
                &intermediate_secret,
            ),
        }
    }

    /// Derive a welcome key and nonce pair to decrypt a `Welcome` message.
    pub(crate) fn derive_welcome_key_nonce(
        &self,
        ciphersuite: &Ciphersuite,
    ) -> (AeadKey, AeadNonce) {
        let welcome_secret = ciphersuite
            .hkdf_expand(&self.secret, b"mls 1.0 welcome", ciphersuite.hash_length())
            .unwrap();
        let welcome_nonce = AeadNonce::from_secret(
            ciphersuite
                .hkdf_expand(&welcome_secret, b"nonce", ciphersuite.aead_nonce_length())
                .unwrap(),
        );
        let welcome_key = AeadKey::from_secret(
            ciphersuite
                .hkdf_expand(&welcome_secret, b"key", ciphersuite.aead_key_length())
                .unwrap(),
            ciphersuite.aead(),
        );
        (welcome_key, welcome_nonce)
    }
}

struct EpochSecret {
    secret: Secret,
}

impl EpochSecret {
    /// Derive a `WelcomeSecret` and an `EpochSecret` from a `MemberSecret`,
    /// consuming it in the process. The `WelcomeSecret` can be obtained by
    /// calling
    fn derive_epoch_secret(
        ciphersuite: &Ciphersuite,
        group_context: &GroupContext,
        member_secret: MemberSecret,
    ) -> Self {
        EpochSecret {
            secret: hkdf_expand_label(
                ciphersuite,
                &member_secret.secret,
                "epoch",
                &group_context.serialize(),
                ciphersuite.hash_length(),
            ),
        }
    }
}

pub struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    fn derive_encryption_secret(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        EncryptionSecret {
            secret: derive_secret(ciphersuite, &epoch_secret.secret, "encryption"),
        }
    }

    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is replaced with `None` in the
    /// process, allowing us to achieve FS.
    pub fn create_secret_tree(self, treesize: LeafIndex) -> Result<SecretTree, KeyScheduleError> {
        Ok(SecretTree::new(self, treesize))
    }

    pub(crate) fn consume_secret(self) -> Secret {
        self.secret
    }

    /// Create a random `EncryptionSecret`. For testing purposes only.
    #[cfg(test)]
    pub fn from_random(length: usize) -> Self {
        EncryptionSecret {
            secret: Secret::from_random(length),
        }
    }
}

/// The `EpochSecrets` contain keys (or secrets), which are accessible outside
/// of the `KeySchedule` and which don't get consumed immediately upon first
/// use.
#[derive(Debug)]
pub struct EpochSecrets {
    sender_data_secret: Secret,
    exporter_secret: Secret,
    confirmation_key: Secret,
}

impl EpochSecrets {
    /// Get the sender_data secret.
    pub(crate) fn sender_data_secret(&self) -> &Secret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &Secret {
        &self.confirmation_key
    }
    /// Derive `EpochSecrets`, as well as an `EncryptionSecret` and an
    /// `InitSecret` from a `MemberSecret` and a given `GroupContext`. This
    /// method is only used when initially creating a new `MlsGroup` state.
    pub(crate) fn derive_epoch_secrets(
        ciphersuite: &Ciphersuite,
        member_secret: MemberSecret,
        group_context: &GroupContext,
    ) -> (Self, InitSecret, EncryptionSecret) {
        let epoch_secret =
            EpochSecret::derive_epoch_secret(ciphersuite, group_context, member_secret);
        let sender_data_secret = derive_secret(ciphersuite, &epoch_secret.secret, "sender data");
        let encryption_secret =
            EncryptionSecret::derive_encryption_secret(ciphersuite, &epoch_secret);
        let exporter_secret = derive_secret(ciphersuite, &epoch_secret.secret, "exporter");
        let confirmation_key = derive_secret(ciphersuite, &epoch_secret.secret, "confirm");
        let init_secret = InitSecret::derive_init_secret(ciphersuite, &epoch_secret);
        let epoch_secrets = EpochSecrets {
            sender_data_secret,
            exporter_secret,
            confirmation_key,
        };
        (epoch_secrets, init_secret, encryption_secret)
    }

    /// Derive a `Secret` from the exporter secret.
    pub fn derive_exported_secret(
        &self,
        ciphersuite: &Ciphersuite,
        label: &str,
        group_context: &GroupContext,
        key_length: usize,
    ) -> Secret {
        let secret = &self.exporter_secret;
        let context = &group_context.serialize();
        let context_hash = &ciphersuite.hash(context);
        hkdf_expand_label(
            ciphersuite,
            &derive_secret(ciphersuite, secret, label),
            label,
            context_hash,
            key_length,
        )
    }
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

struct HkdfLabel {
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
