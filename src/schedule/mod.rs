//! This module represents the key schedule as introduced in Section 8 of the
//! MLS specification. The key schedule evolves in epochs, where in each epoch
//! new key material is injected.
//!
//! The flow of the key schedule is as follows (from Section 8 of the MLS
//! specification):
//!
//! ```text
//!                  init_secret_[n-1]
//!                         |
//!                         V
//!    commit_secret -> KDF.Extract
//!                         |
//!                         V
//!                   DeriveSecret(., "joiner")
//!                         |
//!                         V
//!                    joiner_secret
//!                         |
//!                         V
//! psk_secret (or 0) -> KDF.Extract (= intermediary_secret)
//!                         |
//!                         +--> DeriveSecret(., "welcome")
//!                         |    = welcome_secret
//!                         |
//!                         V
//!                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//!                         |
//!                         V
//!                    epoch_secret
//!                         |
//!                         +--> DeriveSecret(., <label>)
//!                         |    = <secret>
//!                         |
//!                         V
//!                   DeriveSecret(., "init")
//!                         |
//!                         V
//!                   init_secret_[n]
//! ```
//!
//! Each of the secrets in the key schedule (with exception of the
//! welcome_secret) is represented by its own struct to ensure that the keys are
//! not confused with one-another and/or that the schedule is not derived
//! out-of-order.

use crate::ciphersuite::*;
use crate::codec::*;
use crate::group::*;
use crate::messages::{proposals::AddProposal, GroupSecrets, PathSecret};
use crate::tree::index::{LeafIndex, NodeIndex};
use crate::tree::private_tree::CommitSecret;
use crate::tree::secret_tree::SecretTree;
use crate::tree::treemath;
use crate::tree::RatchetTree;

use serde::{Deserialize, Serialize};

pub mod codec;
pub(crate) mod psk;

/// The `InitSecret` is used to connect the next epoch to the current one.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InitSecret {
    secret: Secret,
}

impl InitSecret {
    /// Derive an `InitSecret` from an `EpochSecret`.
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        InitSecret {
            secret: epoch_secret.secret.derive_secret(ciphersuite, "init"),
        }
    }

    /// Sample a fresh, random `InitSecret` for the creation of a new group.
    pub(crate) fn random(length: usize) -> Self {
        InitSecret {
            secret: Secret::random(length),
        }
    }
}

pub(crate) struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from an optional `CommitSecret` and an
    /// `EpochSecrets` object, which contains the necessary `InitSecret`. The
    /// `CommitSecret` needs to be present if the current commit is not an
    /// Add-only commit. TODO: For now, this takes a reference to a
    /// `CommitSecret` as input. This should change with #224.
    pub(crate) fn from_commit_and_init_secret(
        ciphersuite: &Ciphersuite,
        commit_secret_option: Option<&CommitSecret>,
        init_secret: &InitSecret,
    ) -> Self {
        let commit_secret_value = commit_secret_option.map(|commit_secret| commit_secret.secret());
        let intermediate_secret =
            ciphersuite.hkdf_extract(commit_secret_value, &init_secret.secret);
        JoinerSecret {
            secret: intermediate_secret.derive_secret(ciphersuite, "joiner"),
        }
    }

    /// Create the `GroupSecrets` for a number of `invited_members` based on a
    /// provisional `RatchetTree`. If `path_secret_option` is `Some`, we need to
    /// include a `path_secret` into the `GroupSecrets`.
    pub(crate) fn group_secrets(
        &self,
        invited_members: Vec<(NodeIndex, AddProposal)>,
        provisional_tree: &RatchetTree,
        mut path_secrets_option: Option<Vec<Secret>>,
    ) -> Result<Vec<PlaintextSecret>, CodecError> {
        // Get a Vector containing the node indices of the direct path to the
        // root from our own leaf.
        let dirpath = treemath::leaf_direct_path(
            provisional_tree.own_node_index(),
            provisional_tree.leaf_count(),
        )
        .expect("create_commit_internal: TreeMath error when computing direct path.");

        let mut plaintext_secrets = vec![];
        for (index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;
            let key_package_hash = key_package.hash();
            let path_secret = match path_secrets_option {
                Some(ref mut path_secrets) => {
                    // Compute the index of the common ancestor lowest in the
                    // tree of our own leaf and the given index.
                    let common_ancestor_index = treemath::common_ancestor_index(
                        index,
                        provisional_tree.own_node_index().into(),
                    );
                    // Get the position of the node index that represents the
                    // common ancestor in the direct path. We can unwrap here,
                    // because the direct path must contain the shared ancestor.
                    let position = dirpath
                        .iter()
                        .position(|&x| x == common_ancestor_index)
                        .unwrap();
                    // We have to clone the element of the vector here to
                    // preserve its order.
                    let path_secret = path_secrets[position].clone();
                    Some(PathSecret { path_secret })
                }
                None => None,
            };
            // Create the GroupSecrets object for the respective member.
            // TODO #141: Implement PSK
            let group_secrets_bytes = GroupSecrets::new_encoded(&self, path_secret, None)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
            });
        }
        Ok(plaintext_secrets)
    }
}

pub(crate) struct PlaintextSecret {
    pub(crate) public_key: HPKEPublicKey,
    pub(crate) group_secrets_bytes: Vec<u8>,
    pub(crate) key_package_hash: Vec<u8>,
}

/// The intermediate secret includes the optional PSK and is used to later
/// derive the welcome secret and epoch secret
pub(crate) struct IntermediateSecret {
    secret: Secret,
}

impl IntermediateSecret {
    /// Derive ans `IntermediateSecret` from a `JoinerSecret` and an optional
    /// PSK.
    pub(crate) fn new(
        ciphersuite: &Ciphersuite,
        joiner_secret: JoinerSecret,
        psk: Option<Secret>,
    ) -> Self {
        Self {
            secret: ciphersuite.hkdf_extract(psk.as_ref(), &joiner_secret.secret),
        }
    }
}

pub(crate) struct WelcomeSecret {
    secret: Secret,
}

impl WelcomeSecret {
    /// Derive a `WelcomeSecret` from to decrypt a `Welcome` message.
    pub(crate) fn new(ciphersuite: &Ciphersuite, intermediate_secret: &IntermediateSecret) -> Self {
        // Unwrapping here is safe, because we know the key is not empty
        let secret = ciphersuite
            .hkdf_expand(
                &intermediate_secret.secret,
                b"welcome",
                ciphersuite.hash_length(),
            )
            .unwrap();
        WelcomeSecret { secret }
    }

    /// Get the `Secret` of the `WelcomeSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Derive an `AeadKey` and an `AeadNonce` from the `WelcomeSecret`,
    /// consuming it in the process.
    pub(crate) fn derive_welcome_key_nonce(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (AeadKey, AeadNonce) {
        let welcome_nonce = AeadNonce::from_welcome_secret(ciphersuite, &self);
        let welcome_key = AeadKey::from_welcome_secret(ciphersuite, &self);
        (welcome_key, welcome_nonce)
    }
}

/// An intermediate secret in the key schedule, the `EpochSecret` is used to
/// create an `EpochSecrets` object and is finally consumed when creating that
/// epoch's `InitSecret`.
pub(crate) struct EpochSecret {
    secret: Secret,
}

impl EpochSecret {
    /// Derive an `EpochSecret` from a `JoinerSecret`
    pub(crate) fn new(
        ciphersuite: &Ciphersuite,
        intermediate_secret: IntermediateSecret,
        group_context: &GroupContext,
    ) -> Self {
        EpochSecret {
            secret: intermediate_secret.secret.kdf_expand_label(
                ciphersuite,
                "epoch",
                &group_context.serialized(),
                ciphersuite.hash_length(),
            ),
        }
    }

    #[cfg(all(test, feature = "test-vectors"))]
    pub(crate) fn from_random(ciphersuite: &Ciphersuite) -> Self {
        Self {
            secret: Secret::random(ciphersuite.hash_length()),
        }
    }
}

/// The `EncryptionSecret` is used to create a `SecretTree`.
pub struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        EncryptionSecret {
            secret: epoch_secret.secret.derive_secret(ciphersuite, "encryption"),
        }
    }

    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is replaced with `None` in the
    /// process, allowing us to achieve FS.
    pub fn create_secret_tree(self, treesize: LeafIndex) -> SecretTree {
        SecretTree::new(self, treesize)
    }

    pub(crate) fn consume_secret(self) -> Secret {
        self.secret
    }

    /// Create a random `EncryptionSecret`. For testing purposes only.
    #[cfg(test)]
    #[doc(hidden)]
    pub fn from_random(length: usize) -> Self {
        EncryptionSecret {
            secret: Secret::random(length),
        }
    }

    #[cfg(all(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.secret.to_vec()
    }
}

#[cfg(test)]
#[doc(hidden)]
impl From<&[u8]> for EncryptionSecret {
    fn from(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from(bytes),
        }
    }
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ExporterSecret {
    secret: Secret,
}

impl ExporterSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "exporter");
        ExporterSecret { secret }
    }

    /// Get the `Secret` of the `ExporterSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

/// A secret that can be used among members to make sure everyone has the same
/// group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct AuthenticationSecret {
    secret: Secret,
}

impl AuthenticationSecret {
    /// Derive an `AuthenticationSecret` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "authentication");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

/// A secret used when joining a group with an external Commit.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ExternalSecret {
    secret: Secret,
}

impl ExternalSecret {
    /// Derive an `ExternalSecret` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "external");
        Self { secret }
    }

    /// Derive the external keypair for External Commits
    pub(crate) fn derive_external_keypair(&self, ciphersuite: &Ciphersuite) -> HPKEKeyPair {
        ciphersuite.derive_hpke_keypair(&self.secret)
    }
}

/// The confirmation key is used to calculate the `ConfirmationTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ConfirmationKey {
    secret: Secret,
}

impl ConfirmationKey {
    /// Derive an `ConfirmationKey` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "confirmation");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

/// The membership key is used to calculate the `MembershipTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MembershipKey {
    secret: Secret,
}

impl MembershipKey {
    /// Derive an `MembershipKey` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "membership");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }
}

/// A secret used in cross-group operations.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ResumptionSecret {
    secret: Secret,
}

impl ResumptionSecret {
    /// Derive an `ResumptionSecret` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "resumption");
        Self { secret }
    }

    /// Get the internal `Secret`.
    // Will be used in #141
    pub(crate) fn _secret(&self) -> &Secret {
        &self.secret
    }
}

/// A key that can be used to derive an `AeadKey` and an `AeadNonce`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct SenderDataSecret {
    secret: Secret,
}

impl SenderDataSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    pub(crate) fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "sender data");
        SenderDataSecret { secret }
    }

    /// Get the `Secret` of the `ExporterSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(all(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn from_random(length: usize) -> Self {
        Self {
            secret: Secret::random(length),
        }
    }

    #[cfg(all(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub fn to_vec(&self) -> Vec<u8> {
        self.secret.to_vec()
    }
}

#[cfg(test)]
#[doc(hidden)]
impl From<&[u8]> for SenderDataSecret {
    fn from(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from(bytes),
        }
    }
}

/// The `EpochSecrets` contain keys (or secrets), which are accessible outside
/// of the `KeySchedule` and which don't get consumed immediately upon first
/// use.
///
/// | Secret                  | Label           |
/// |:------------------------|:----------------|
/// | `sender_data_secret`    | "sender data"   |
/// | `encryption_secret`     | "encryption"    |
/// | `exporter_secret`       | "exporter"      |
/// | `authentication_secret` | "authentication"|
/// | `external_secret`       | "external"      |
/// | `confirmation_key`      | "confirm"       |
/// | `membership_key`        | "membership"    |
/// | `resumption_secret`     | "resumption"    |
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct EpochSecrets {
    sender_data_secret: SenderDataSecret,
    pub(crate) exporter_secret: ExporterSecret,
    authentication_secret: AuthenticationSecret,
    external_secret: ExternalSecret,
    confirmation_key: ConfirmationKey,
    pub(crate) membership_key: MembershipKey,
    resumption_secret: ResumptionSecret,
}

impl EpochSecrets {
    /// Get the sender_data secret.
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Authentication secret
    pub(crate) fn authentication_secret(&self) -> &AuthenticationSecret {
        &self.authentication_secret
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// Derive `EpochSecrets`, as well as an `EncryptionSecret` and an
    /// `InitSecret` from an `EpochSecret` and a given `GroupContext`. This
    /// method is only used when initially creating a new `MlsGroup` state.
    pub(crate) fn derive_epoch_secrets(
        ciphersuite: &Ciphersuite,
        epoch_secret: EpochSecret,
    ) -> (Self, InitSecret, EncryptionSecret) {
        let sender_data_secret = SenderDataSecret::new(ciphersuite, &epoch_secret);
        let encryption_secret = EncryptionSecret::new(ciphersuite, &epoch_secret);
        let exporter_secret = ExporterSecret::new(ciphersuite, &epoch_secret);
        let authentication_secret = AuthenticationSecret::new(ciphersuite, &epoch_secret);
        let external_secret = ExternalSecret::new(ciphersuite, &epoch_secret);
        let confirmation_key = ConfirmationKey::new(ciphersuite, &epoch_secret);
        let membership_key = MembershipKey::new(ciphersuite, &epoch_secret);
        let resumption_secret = ResumptionSecret::new(ciphersuite, &epoch_secret);

        let init_secret = InitSecret::new(ciphersuite, &epoch_secret);
        let epoch_secrets = EpochSecrets {
            sender_data_secret,
            exporter_secret,
            authentication_secret,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_secret,
        };
        (epoch_secrets, init_secret, encryption_secret)
    }

    #[cfg(all(test, feature = "test-vectors"))]
    #[doc(hidden)]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }
}
