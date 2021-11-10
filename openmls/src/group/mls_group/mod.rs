use log::{debug, trace};
use psk::{PreSharedKeys, PskSecret};

pub mod create_commit;
pub mod create_commit_params;
mod new_from_welcome;
pub mod proposals;
pub mod staged_commit;
#[cfg(test)]
mod test_create_commit_params;
#[cfg(test)]
mod test_duplicate_extension;
#[cfg(test)]
mod test_mls_group;
#[cfg(test)]
mod test_proposals;

use crate::ciphersuite::signable::{Signable, Verifiable};
use crate::config::Config;
use crate::credentials::{CredentialBundle, CredentialError};
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::public_group_state::{PublicGroupState, PublicGroupStateTbs};
use crate::messages::{proposals::*, *};
use crate::schedule::*;
use crate::tree::{index::*, node::*, secret_tree::*, *};
use crate::{ciphersuite::*, config::ProtocolVersion};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
    Deserialize, Deserializer, Serialize,
};
use std::cell::{Ref, RefCell};
use std::convert::TryFrom;
use std::io::{Error, Read, Write};

use std::cell::RefMut;
use tls_codec::Serialize as TlsSerializeTrait;

use super::errors::{ExporterError, MlsGroupError, PskError};

pub type CreateCommitResult =
    Result<(MlsPlaintext, Option<Welcome>, Option<KeyPackageBundle>), MlsGroupError>;

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
    use_ratchet_tree_extension: bool,
    // The MLS protocol version used in this group.
    mls_version: ProtocolVersion,
}

implement_persistence!(
    MlsGroup,
    group_context,
    epoch_secrets,
    secret_tree,
    tree,
    interim_transcript_hash,
    use_ratchet_tree_extension,
    mls_version
);

/// Public `MlsGroup` functions.
impl MlsGroup {
    pub fn new(
        id: &[u8],
        ciphersuite_name: CiphersuiteName,
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle: KeyPackageBundle,
        config: MlsGroupConfig,
        psk_option: impl Into<Option<PskSecret>>,
        version: impl Into<Option<ProtocolVersion>>,
    ) -> Result<Self, MlsGroupError> {
        debug!("Created group {:x?}", id);
        trace!(" >>> with {:?}, {:?}", ciphersuite_name, config);
        let group_id = GroupId { value: id.into() };
        let ciphersuite = Config::ciphersuite(ciphersuite_name)?;
        let tree = RatchetTree::new(backend, key_package_bundle);
        // TODO #186: Implement extensions
        let extensions: Vec<Extension> = Vec::new();

        let group_context = GroupContext::create_initial_group_context(
            ciphersuite,
            group_id,
            tree.tree_hash(backend),
            &extensions,
        )?;
        let commit_secret = tree.private_tree().commit_secret();
        // Derive an initial joiner secret based on the commit secret.
        // Derive an epoch secret from the joiner secret.
        // We use a random `InitSecret` for initialization.
        let version = version.into().unwrap_or_default();
        let joiner_secret = JoinerSecret::new(
            backend,
            commit_secret,
            &InitSecret::random(ciphersuite, backend, version),
        );

        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_option);
        key_schedule.add_context(backend, &group_context)?;
        let epoch_secrets = key_schedule.epoch_secrets(backend, true)?;

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
            use_ratchet_tree_extension: config.add_ratchet_tree_extension,
            mls_version: version,
        })
    }

    // Join a group from a welcome message
    pub fn new_from_welcome(
        welcome: Welcome,
        nodes_option: Option<Vec<Option<Node>>>,
        kpb: KeyPackageBundle,
        psk_fetcher_option: Option<PskFetcher>,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, MlsGroupError> {
        Ok(Self::new_from_welcome_internal(
            welcome,
            nodes_option,
            kpb,
            psk_fetcher_option,
            backend,
        )?)
    }

    // === Create handshake messages ===
    // TODO: share functionality between these.

    // 11.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    pub fn create_add_proposal(
        &self,
        framing_parameters: FramingParameters,

        credential_bundle: &CredentialBundle,
        joiner_key_package: KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        MlsPlaintext::new_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.epoch_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.2. Update
    // struct {
    //     KeyPackage key_package;
    // } Update;
    pub fn create_update_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        key_package: KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let update_proposal = UpdateProposal { key_package };
        let proposal = Proposal::Update(update_proposal);
        MlsPlaintext::new_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.epoch_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.3. Remove
    // struct {
    //     uint32 removed;
    // } Remove;
    pub fn create_remove_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        removed_index: LeafIndex,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let remove_proposal = RemoveProposal {
            removed: removed_index.into(),
        };
        let proposal = Proposal::Remove(remove_proposal);
        MlsPlaintext::new_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.epoch_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // 11.1.4. PreSharedKey
    // struct {
    //     PreSharedKeyID psk;
    // } PreSharedKey;
    pub fn create_presharedkey_proposal(
        &self,
        framing_parameters: FramingParameters,
        credential_bundle: &CredentialBundle,
        psk: PreSharedKeyId,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        let presharedkey_proposal = PreSharedKeyProposal::new(psk);
        let proposal = Proposal::PreSharedKey(presharedkey_proposal);
        MlsPlaintext::new_proposal(
            framing_parameters,
            self.sender_index(),
            proposal,
            credential_bundle,
            self.context(),
            self.epoch_secrets().membership_key(),
            backend,
        )
        .map_err(|e| e.into())
    }

    // Create application message
    pub fn create_application_message(
        &mut self,
        aad: &[u8],
        msg: &[u8],
        credential_bundle: &CredentialBundle,
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsCiphertext, MlsGroupError> {
        let mls_plaintext = MlsPlaintext::new_application(
            self.sender_index(),
            aad,
            msg,
            credential_bundle,
            self.context(),
            self.epoch_secrets().membership_key(),
            backend,
        )?;
        self.encrypt(mls_plaintext, padding_size, backend)
    }

    // Encrypt an MlsPlaintext into an MlsCiphertext
    pub fn encrypt(
        &mut self,
        mls_plaintext: MlsPlaintext,
        padding_size: usize,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsCiphertext, MlsGroupError> {
        log::trace!("{:?}", mls_plaintext.confirmation_tag());
        MlsCiphertext::try_from_plaintext(
            &mls_plaintext,
            self.ciphersuite,
            backend,
            self.context(),
            self.sender_index(),
            Secrets {
                epoch_secrets: self.epoch_secrets(),
                secret_tree: &mut self.secret_tree_mut(),
            },
            padding_size,
        )
        .map_err(MlsGroupError::MlsCiphertextError)
    }

    /// Decrypt an MlsCiphertext into an MlsPlaintext
    pub fn decrypt(
        &mut self,
        mls_ciphertext: &MlsCiphertext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<VerifiableMlsPlaintext, MlsGroupError> {
        Ok(mls_ciphertext.to_plaintext(
            self.ciphersuite(),
            backend,
            &self.epoch_secrets,
            &mut self.secret_tree.borrow_mut(),
        )?)
    }

    /// Set the context of the [`VerifiableMlsPlaintext`] (if it has not been
    /// set already), verify it and return the [`MlsPlaintext`].
    pub fn verify(
        &self,
        mut verifiable: VerifiableMlsPlaintext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsPlaintext, MlsGroupError> {
        // Verify the signature on the plaintext.
        let tree = self.tree();

        let node = &tree
            .nodes
            .get(NodeIndex::from(verifiable.sender_index()).as_usize())
            .ok_or(MlsPlaintextError::UnknownSender)?;
        let credential = if let Some(kp) = node.key_package.as_ref() {
            kp.credential()
        } else {
            return Err(MlsPlaintextError::UnknownSender.into());
        };
        // Set the context if it has not been set already.
        if !verifiable.has_context() {
            verifiable.set_context(self.context().tls_serialize_detached()?);
        }

        // TODO: what about the tags?
        verifiable
            .verify(backend, credential)
            .map_err(|e| MlsPlaintextError::from(e).into())
    }

    /// Set the context of the `UnverifiedMlsPlaintext` and verify its
    /// membership tag.
    pub fn verify_membership_tag(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        verifiable_mls_plaintext: &mut VerifiableMlsPlaintext,
    ) -> Result<(), MlsGroupError> {
        verifiable_mls_plaintext.set_context(self.context().tls_serialize_detached()?);
        Ok(verifiable_mls_plaintext
            .verify_membership(backend, self.epoch_secrets().membership_key())?)
    }

    /// Exporter
    pub fn export_secret(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, MlsGroupError> {
        if key_length > u16::MAX.into() {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExporterError::KeyLengthTooLong.into());
        }
        Ok(self.epoch_secrets.exporter_secret().derive_exported_secret(
            self.ciphersuite(),
            backend,
            label,
            context,
            key_length,
        ))
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.epoch_secrets().authentication_secret().export()
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
    pub fn extensions(&self) -> Vec<Extension> {
        let extensions: Vec<Extension> = if self.use_ratchet_tree_extension {
            vec![Extension::RatchetTree(RatchetTreeExtension::new(
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
        backend: &impl OpenMlsCryptoProvider,
        credential_bundle: &CredentialBundle,
    ) -> Result<PublicGroupState, CredentialError> {
        let pgs_tbs = PublicGroupStateTbs::new(backend, self);
        pgs_tbs.sign(backend, credential_bundle)
    }

    /// Returns `true` if the group uses the ratchet tree extension anf `false
    /// otherwise
    pub fn use_ratchet_tree_extension(&self) -> bool {
        self.use_ratchet_tree_extension
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

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets {
        &mut self.epoch_secrets
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }
}

// Callback functions

/// This callback function is used in several places in `MlsGroup`.
/// It gets called whenever the key schedule is advanced and references to PSKs
/// are encountered. Since the PSKs are to be trandmitted out-of-band, they need
/// to be fetched from wherever they are stored.
pub type PskFetcher =
    fn(psks: &PreSharedKeys, ciphersuite: &'static Ciphersuite) -> Option<Vec<Secret>>;

// Helper functions

pub(crate) fn update_confirmed_transcript_hash(
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    mls_plaintext_commit_content: &MlsPlaintextCommitContent,
    interim_transcript_hash: &[u8],
) -> Result<Vec<u8>, tls_codec::Error> {
    let commit_content_bytes = mls_plaintext_commit_content.tls_serialize_detached()?;
    Ok(ciphersuite.hash(
        backend,
        &[interim_transcript_hash, &commit_content_bytes].concat(),
    ))
}

pub(crate) fn update_interim_transcript_hash(
    ciphersuite: &Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    mls_plaintext_commit_auth_data: &MlsPlaintextCommitAuthData,
    confirmed_transcript_hash: &[u8],
) -> Result<Vec<u8>, tls_codec::Error> {
    let commit_auth_data_bytes = mls_plaintext_commit_auth_data.tls_serialize_detached()?;
    Ok(ciphersuite.hash(
        backend,
        &[confirmed_transcript_hash, &commit_auth_data_bytes].concat(),
    ))
}

fn psk_output(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    psk_fetcher_option: Option<PskFetcher>,
    presharedkeys: &PreSharedKeys,
) -> Result<Option<PskSecret>, PskError> {
    if !presharedkeys.psks.is_empty() {
        // Check if a PSK fetcher function was provided
        match psk_fetcher_option {
            Some(psk_fetcher) => {
                // Try to fetch the PSKs with the IDs
                match psk_fetcher(presharedkeys, ciphersuite) {
                    Some(psks) => {
                        // Combine the PSKs in to a PskSecret
                        let psk_secret = PskSecret::new(
                            ciphersuite,
                            backend,
                            presharedkeys.psks.as_slice(),
                            &psks,
                        )?;
                        Ok(Some(psk_secret))
                    }
                    None => Err(PskError::PskIdNotFound),
                }
            }
            None => Err(PskError::NoPskFetcherProvided),
        }
    } else {
        Ok(None)
    }
}
