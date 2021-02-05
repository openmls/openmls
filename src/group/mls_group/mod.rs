use log::{debug, trace};

mod apply_commit;
mod create_commit;
mod new_from_welcome;
#[cfg(test)]
mod test_mls_group;

use crate::ciphersuite::*;
use crate::codec::*;
use crate::config::Config;
use crate::credentials::{CredentialBundle, CredentialError};
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::tree::{index::*, node::*, secret_tree::*, *};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::cell::{Ref, RefCell};
use std::convert::TryFrom;
use std::io::{Error, Read, Write};

use std::cell::RefMut;

use super::errors::ExporterError;

pub type CreateCommitResult =
    Result<(MLSPlaintext, Option<Welcome>, Option<KeyPackageBundle>), GroupError>;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MlsGroup {
    ciphersuite: &'static Ciphersuite,
    group_context: GroupContext,
    epoch_secrets: EpochSecrets,
    secret_tree: RefCell<SecretTree>,
    tree: RefCell<RatchetTree>,
    interim_transcript_hash: Vec<u8>,
    // Group config.
    // Set to true if the ratchet tree extension is added to the `GroupInfo`.
    // Defaults to `false`.
    add_ratchet_tree_extension: bool,
}

implement_persistence!(
    MlsGroup,
    group_context,
    epoch_secrets,
    secret_tree,
    tree,
    interim_transcript_hash,
    add_ratchet_tree_extension
);

/// Public `MlsGroup` functions.
impl MlsGroup {
    pub fn new(
        id: &[u8],
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
        config: GroupConfig,
    ) -> Result<Self, GroupError> {
        debug!("Created group {:x?}", id);
        trace!(" >>> with {:?}, {:?}", ciphersuite_name, config);
        let group_id = GroupId { value: id.to_vec() };
        let ciphersuite = Config::ciphersuite(ciphersuite_name)?;
        let tree = RatchetTree::new(ciphersuite, key_package_bundle);
        // TODO #186: Implement extensions
        let group_context = GroupContext::create_initial_group_context(
            ciphersuite,
            group_id,
            tree.tree_hash(),
            &[],
        )?;
        let commit_secret = tree.private_tree().commit_secret();
        // Derive an initial joiner secret based on the commit secret.
        // Derive an epoch secret from the joiner secret.
        // We use a random `InitSecret` for initialization.
        let joiner_secret = JoinerSecret::new(
            ciphersuite,
            commit_secret,
            &InitSecret::random(ciphersuite.hash_length()),
        );

        // TODO #141: Implement PSK
        let mut key_schedule = KeySchedule::init(ciphersuite, joiner_secret, None);
        key_schedule.add_context(&group_context)?;
        let epoch_secrets = key_schedule.epoch_secrets(true)?;

        let secret_tree = epoch_secrets
            .encryption_secret()
            .create_secret_tree(LeafIndex::from(1u32));
        let interim_transcript_hash = vec![];
        Ok(MlsGroup {
            ciphersuite,
            group_context,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: RefCell::new(tree),
            interim_transcript_hash,
            add_ratchet_tree_extension: config.add_ratchet_tree_extension,
        })
    }

    // Join a group from a welcome message
    pub fn new_from_welcome(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        kpb: KeyPackageBundle,
    ) -> Result<Self, GroupError> {
        Ok(Self::new_from_welcome_internal(welcome, nodes_option, kpb)?)
    }

    // === Create handshake messages ===
    // TODO: share functionality between these.

    // 11.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    pub fn create_add_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        joiner_key_package: KeyPackage,
    ) -> Result<MLSPlaintext, GroupError> {
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        MLSPlaintext::new_from_proposal_member(
            self.ciphersuite,
            self.sender_index(),
            aad,
            proposal,
            credential_bundle,
            &self.context(),
            self.epoch_secrets().membership_key(),
        )
        .map_err(GroupError::CodecError)
    }

    // 11.1.2. Update
    // struct {
    //     KeyPackage key_package;
    // } Update;
    pub fn create_update_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        key_package: KeyPackage,
    ) -> Result<MLSPlaintext, GroupError> {
        let update_proposal = UpdateProposal { key_package };
        let proposal = Proposal::Update(update_proposal);
        MLSPlaintext::new_from_proposal_member(
            self.ciphersuite,
            self.sender_index(),
            aad,
            proposal,
            credential_bundle,
            &self.context(),
            self.epoch_secrets().membership_key(),
        )
        .map_err(GroupError::CodecError)
    }

    // 11.1.3. Remove
    // struct {
    //     uint32 removed;
    // } Remove;
    pub fn create_remove_proposal(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        removed_index: LeafIndex,
    ) -> Result<MLSPlaintext, GroupError> {
        let remove_proposal = RemoveProposal {
            removed: removed_index.into(),
        };
        let proposal = Proposal::Remove(remove_proposal);
        MLSPlaintext::new_from_proposal_member(
            self.ciphersuite,
            self.sender_index(),
            aad,
            proposal,
            credential_bundle,
            &self.context(),
            self.epoch_secrets().membership_key(),
        )
        .map_err(GroupError::CodecError)
    }

    // === ===

    // 11.2. Commit
    // opaque ProposalID<0..255>;
    //
    // struct {
    //     ProposalID proposals<0..2^32-1>;
    //     optional<UpdatePath> path;
    // } Commit;
    pub fn create_commit(
        &self,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[&MLSPlaintext],
        proposals_by_value: &[&Proposal],
        force_self_update: bool,
    ) -> CreateCommitResult {
        self.create_commit_internal(
            aad,
            credential_bundle,
            proposals_by_reference,
            proposals_by_value,
            force_self_update,
        )
    }

    // Apply a Commit message
    pub fn apply_commit(
        &mut self,
        mls_plaintext: &MLSPlaintext,
        proposals: &[&MLSPlaintext],
        own_key_packages: &[KeyPackageBundle],
    ) -> Result<(), GroupError> {
        Ok(self.apply_commit_internal(mls_plaintext, proposals, own_key_packages)?)
    }

    // Create application message
    pub fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        credential_bundle: &CredentialBundle,
        padding_size: usize,
    ) -> Result<MLSCiphertext, GroupError> {
        let mls_plaintext = MLSPlaintext::new_from_application(
            self.ciphersuite,
            self.sender_index(),
            aad,
            msg,
            credential_bundle,
            &self.context(),
            self.epoch_secrets().membership_key(),
        )?;
        self.encrypt(mls_plaintext, padding_size)
    }

    // Encrypt an MLSPlaintext into an MLSCiphertext
    pub fn encrypt(
        &mut self,
        mls_plaintext: MLSPlaintext,
        padding_size: usize,
    ) -> Result<MLSCiphertext, GroupError> {
        MLSCiphertext::try_from_plaintext(
            &mls_plaintext,
            &self.ciphersuite,
            self.context(),
            self.sender_index(),
            self.epoch_secrets(),
            &mut self.secret_tree_mut(),
            padding_size,
        )
        .map_err(GroupError::MLSCiphertextError)
    }

    /// Decrypt an MLSCiphertext into an MLSPlaintext
    pub fn decrypt(
        &mut self,
        mls_ciphertext: &MLSCiphertext,
    ) -> Result<MLSPlaintext, MLSCiphertextError> {
        let mls_plaintext = mls_ciphertext.to_plaintext(
            self.ciphersuite(),
            &self.epoch_secrets,
            &mut self.secret_tree.borrow_mut(),
        )?;

        // Verify the signature. MLSCiphertext messages don't have a membership tag, so
        // we don't have to verify that.
        self.verify_signature(&mls_plaintext)?;

        Ok(mls_plaintext)
    }

    /// Verify the signature of an MLSPlaintext
    pub fn verify_signature(&self, mls_plaintext: &MLSPlaintext) -> Result<(), MLSPlaintextError> {
        let tree = self.tree();

        let node = &tree.nodes[mls_plaintext.sender()];
        let credential = if let Some(kp) = node.key_package.as_ref() {
            kp.credential()
        } else {
            return Err(MLSPlaintextError::UnknownSender);
        };

        let serialized_context = self.context().serialized();

        mls_plaintext
            .verify_signature(serialized_context, credential)
            .map_err(|_| MLSPlaintextError::InvalidSignature)
    }

    /// Verify the membership tag an MLSPlaintext
    pub fn verify_membership_tag(
        &self,
        mls_plaintext: &MLSPlaintext,
    ) -> Result<(), MLSPlaintextError> {
        let serialized_context = self.context().serialized();

        mls_plaintext
            .verify_membership_tag(
                self.ciphersuite,
                serialized_context,
                self.epoch_secrets().membership_key(),
            )
            .map_err(|_| MLSPlaintextError::InvalidSignature)
    }

    /// Exporter
    pub fn export_secret(&self, label: &str, key_length: usize) -> Result<Vec<u8>, GroupError> {
        // TODO: This should throw an error. Generally, keys length should be
        // checked. (see #228).
        if key_length > u16::MAX.into() {
            return Err(ExporterError::KeyLengthTooLong.into());
        }
        Ok(self.epoch_secrets.exporter_secret().derive_exported_secret(
            self.ciphersuite(),
            label,
            &self.context(),
            key_length,
        ))
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.epoch_secrets()
            .authentication_secret()
            .secret()
            .to_bytes()
            .to_vec()
    }

    /// Loads the state from persisted state
    pub fn load<R: Read>(reader: R) -> Result<MlsGroup, Error> {
        serde_json::from_reader(reader).map_err(|e| e.into())
    }

    /// Persists the state
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let serialized_mls_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_mls_group.into_bytes())
    }

    /// Returns the ratchet tree
    pub fn tree(&self) -> Ref<RatchetTree> {
        self.tree.borrow()
    }

    /// Get the ciphersuite implementation used in this group.
    pub fn ciphersuite(&self) -> &'static Ciphersuite {
        self.ciphersuite
    }

    /// Get the group context
    pub fn context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Get the group ID
    pub fn group_id(&self) -> &GroupId {
        &self.group_context.group_id
    }

    /// Get the groups extensions.
    /// Right now this is limited to the ratchet tree extension which is built
    /// on the fly when calling this function.
    pub fn extensions(&self) -> Vec<Box<dyn Extension>> {
        let extensions: Vec<Box<dyn Extension>> = if self.add_ratchet_tree_extension {
            vec![Box::new(RatchetTreeExtension::new(
                self.tree().public_key_tree_copy(),
            ))]
        } else {
            Vec::new()
        };
        extensions
    }

    /// Export the `PublicGroupState`
    pub fn export_public_group_state(
        &self,
        credential_bundle: &CredentialBundle,
    ) -> Result<PublicGroupState, CredentialError> {
        PublicGroupState::new(self, credential_bundle)
    }
}

// Private and crate functions
impl MlsGroup {
    pub(crate) fn sender_index(&self) -> LeafIndex {
        self.tree.borrow().own_node_index()
    }

    pub(crate) fn epoch_secrets(&self) -> &EpochSecrets {
        &self.epoch_secrets
    }

    pub(crate) fn secret_tree_mut(&self) -> RefMut<SecretTree> {
        self.secret_tree.borrow_mut()
    }

    /// Current interim transcript hash of the group
    pub(crate) fn interim_transcript_hash(&self) -> &[u8] {
        &self.interim_transcript_hash
    }

    #[cfg(test)]
    pub(crate) fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets {
        &mut self.epoch_secrets
    }

    #[cfg(test)]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}

// Helper functions

fn update_confirmed_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext_commit_content: &MLSPlaintextCommitContent,
    interim_transcript_hash: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let commit_content_bytes = mls_plaintext_commit_content.encode_detached()?;
    Ok(ciphersuite.hash(&[interim_transcript_hash, &commit_content_bytes].concat()))
}

fn update_interim_transcript_hash(
    ciphersuite: &Ciphersuite,
    mls_plaintext_commit_auth_data: &MLSPlaintextCommitAuthData,
    confirmed_transcript_hash: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let commit_auth_data_bytes = mls_plaintext_commit_auth_data.encode_detached().unwrap();
    Ok(ciphersuite.hash(&[confirmed_transcript_hash, &commit_auth_data_bytes].concat()))
}
