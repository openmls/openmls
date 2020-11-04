use crate::creds::CredentialBundle;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::tree::{index::LeafIndex, node::*};

pub trait Api: Sized {
    /// Create a new group.
    fn new(
        group_id: &[u8],
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
        config: GroupConfig,
    ) -> Self;
    /// Join a group from a Welcome message
    fn new_from_welcome(
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError>;

    // Create handshake messages

    /// Create an `AddProposal`
    fn create_add_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        joiner_key_package: KeyPackage,
    ) -> MLSPlaintext;
    /// Create an `UpdateProposal`
    fn create_update_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        key_package: KeyPackage,
    ) -> MLSPlaintext;
    /// Create a `RemoveProposal`
    fn create_remove_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        removed_index: LeafIndex,
    ) -> MLSPlaintext;
    /// Create a `Commit` and an optional `Welcome`
    fn create_commit(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals: Vec<MLSPlaintext>,
        force_self_update: bool,
    ) -> CreateCommitResult;

    /// Apply a `Commit` message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<MLSPlaintext>,
        own_key_packages: &[KeyPackageBundle],
    ) -> Result<(), ApplyCommitError>;

    /// Create application message
    fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        credential_bundle: &CredentialBundle,
    ) -> MLSCiphertext;

    /// Encrypt an MLS message
    fn encrypt(&mut self, mls_plaintext: MLSPlaintext) -> MLSCiphertext;
    /// Decrypt an MLS message
    fn decrypt(&mut self, mls_ciphertext: MLSCiphertext) -> Result<MLSPlaintext, DecryptionError>;

    /// Export a secret through the exporter
    fn export_secret(&self, label: &str, key_length: usize) -> Vec<u8>;
}

pub type CreateCommitResult =
    Result<(MLSPlaintext, Option<Welcome>, Option<KeyPackageBundle>), CreateCommitError>;
