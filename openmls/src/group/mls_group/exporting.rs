use errors::{ExportGroupInfoError, ExportSecretError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};

use crate::{
    ciphersuite::HpkePublicKey,
    extensions::errors::InvalidExtensionError,
    schedule::{EpochAuthenticator, ResumptionPskSecret},
};
#[cfg(feature = "extensions-draft")]
use crate::{
    component::ComponentId,
    group::{PendingSafeExportSecretError, SafeExportSecretError},
};

#[cfg(feature = "virtual-clients-draft")]
use crate::{
    binary_tree::array_representation::TreeSize,
    components::vc_derivation_info::{
        EmulatorEpochSecret, EpochId, RegisteredVcDerivationEpoch, VcDerivationEpochState,
        VC_COMPONENT_ID,
    },
    components::vc_operation_tree::OperationSecretTree,
    group::mls_group::errors::RegisterVcDerivationEpochError,
    schedule::application_export_tree::ApplicationExportTree,
};

use super::*;

/// The emulation-group coordinates of the group epoch a derivation epoch is
/// registered for. All values describe the *target* epoch, which for a merge is
/// the epoch the commit moves the group into, not the one it is merged from.
#[cfg(feature = "virtual-clients-draft")]
pub(crate) struct VcDerivationEpochParams<'a> {
    /// Group id of the emulation group.
    pub(crate) group_id: &'a GroupId,
    /// Ciphersuite of the emulation group.
    pub(crate) ciphersuite: Ciphersuite,
    /// The emulation group's epoch this derivation epoch is sourced from.
    pub(crate) group_epoch: GroupEpoch,
    /// The registering client's own leaf index in the emulation group.
    pub(crate) own_leaf_index: LeafNodeIndex,
    /// Number of leaves in the emulation group's ratchet tree.
    pub(crate) tree_size: TreeSize,
}

/// Derive and persist the virtual-clients derivation-epoch state for one epoch
/// of an emulation group.
///
/// Sources the per-derivation-epoch root secret by puncturing
/// `export_tree` under [`VC_COMPONENT_ID`], derives the [`EpochId`], the AEAD
/// key, the epoch base secret and the reuse-guard and generation-id secrets,
/// builds the per-epoch operation secret tree (sized like the emulation group's
/// ratchet tree), and persists the tree, the per-epoch state and the
/// newest-derivation-epoch record. Returns the derived [`EpochId`].
///
/// The caller owns `export_tree` and is responsible for persisting it after
/// this call, so that the puncture is not lost.
///
/// A registration consumes the forward-secure exporter, so it can run at most
/// once per group epoch. A repeated call for an already-registered group epoch
/// returns the recorded [`EpochId`] and leaves both the exporter and the
/// already-persisted operation secret tree untouched.
#[cfg(feature = "virtual-clients-draft")]
pub(crate) fn register_vc_derivation_epoch<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
    crypto: &Crypto,
    storage: &Storage,
    export_tree: &mut ApplicationExportTree,
    params: VcDerivationEpochParams<'_>,
) -> Result<EpochId, RegisterVcDerivationEpochError<Storage::Error>> {
    let VcDerivationEpochParams {
        group_id,
        ciphersuite,
        group_epoch,
        own_leaf_index,
        tree_size,
    } = params;

    let registered: Option<RegisteredVcDerivationEpoch> = storage
        .registered_vc_derivation_epoch(group_id)
        .map_err(|e| {
            log::error!("vc: load newest derivation epoch before registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    if let Some(registered) = registered {
        if registered.group_epoch == group_epoch {
            return Ok(registered.epoch_id);
        }
    }

    let bytes = export_tree.safe_export_secret(crypto, ciphersuite, VC_COMPONENT_ID)?;
    let emulator_epoch_secret = EmulatorEpochSecret::new(bytes.as_slice());
    let epoch_id = emulator_epoch_secret.derive_epoch_id(crypto, ciphersuite)?;
    let epoch_encryption_key =
        emulator_epoch_secret.derive_epoch_encryption_key(crypto, ciphersuite)?;
    let epoch_base_secret = emulator_epoch_secret.derive_epoch_base_secret(crypto, ciphersuite)?;
    let reuse_guard_secret =
        emulator_epoch_secret.derive_reuse_guard_secret(crypto, ciphersuite)?;
    let generation_id_secret =
        emulator_epoch_secret.derive_generation_id_secret(crypto, ciphersuite)?;
    let operation_tree = OperationSecretTree::new(epoch_base_secret, tree_size);
    let state = VcDerivationEpochState::new(
        group_epoch,
        own_leaf_index,
        epoch_encryption_key,
        reuse_guard_secret,
        generation_id_secret,
        tree_size,
        ciphersuite,
    );
    let registered = RegisteredVcDerivationEpoch {
        group_epoch,
        epoch_id,
    };

    storage
        .write_vc_operation_tree(&registered.epoch_id, &operation_tree)
        .map_err(|e| {
            log::error!("vc: persist operation tree at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    storage
        .write_vc_derivation_epoch_state(&registered.epoch_id, &state)
        .map_err(|e| {
            log::error!("vc: persist derivation epoch state at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;
    storage
        .write_registered_vc_derivation_epoch(group_id, &registered)
        .map_err(|e| {
            log::error!("vc: record newest derivation epoch at registration failed: {e:?}");
            RegisterVcDerivationEpochError::Storage(e)
        })?;

    Ok(registered.epoch_id)
}

impl MlsGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch.
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    /// Returns [`ExportSecretError::GroupStateError(MlsGroupStateError::UseAfterEviction)`](MlsGroupStateError::UseAfterEviction)
    /// if the group is not active.
    pub fn export_secret<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExportSecretError> {
        if key_length > u16::MAX as usize {
            log::error!("Got a key that is larger than u16::MAX");
            return Err(ExportSecretError::KeyLengthTooLong);
        }

        if self.is_active() {
            Ok(self
                .group_epoch_secrets
                .exporter_secret()
                .derive_exported_secret(self.ciphersuite(), crypto, label, context, key_length)
                .map_err(LibraryError::unexpected_crypto_error)?)
        } else {
            Err(ExportSecretError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ))
        }
    }

    /// Export a secret from the forward secure exporter for the component with
    /// the given component ID.
    #[cfg(feature = "extensions-draft")]
    pub fn safe_export_secret<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
        &mut self,
        crypto: &Crypto,
        storage: &Storage,
        component_id: ComponentId,
    ) -> Result<Vec<u8>, SafeExportSecretError<Storage::Error>> {
        if !self.is_active() {
            return Err(SafeExportSecretError::GroupState(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let group_id = self.public_group.group_id();
        let ciphersuite = self.ciphersuite();
        let Some(application_export_tree) = self.application_export_tree.as_mut() else {
            return Err(SafeExportSecretError::Unsupported);
        };
        let component_secret =
            application_export_tree.safe_export_secret(crypto, ciphersuite, component_id)?;
        storage
            .write_application_export_tree(group_id, application_export_tree)
            .map_err(SafeExportSecretError::Storage)?;

        Ok(component_secret.as_slice().to_vec())
    }

    /// Export a secret from the forward secure exporter of the pending commit
    /// state for the component with the given component ID.
    #[cfg(feature = "extensions-draft")]
    pub fn safe_export_secret_from_pending<Provider: StorageProvider>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        storage: &Provider,
        component_id: ComponentId,
    ) -> Result<Vec<u8>, PendingSafeExportSecretError<Provider::Error>> {
        let group_id = self.group_id().clone();
        let MlsGroupState::PendingCommit(ref mut group_state) = self.group_state else {
            return Err(PendingSafeExportSecretError::NoPendingCommit);
        };
        let PendingCommitState::Member(ref mut staged_commit) = **group_state else {
            return Err(PendingSafeExportSecretError::NotGroupMember);
        };
        let secret = staged_commit.safe_export_secret(crypto, component_id)?;
        storage
            .write_group_state(&group_id, &self.group_state)
            .map_err(PendingSafeExportSecretError::Storage)?;
        Ok(secret.as_slice().to_vec())
    }

    /// Returns the epoch authenticator of the current epoch.
    pub fn epoch_authenticator(&self) -> &EpochAuthenticator {
        self.group_epoch_secrets().epoch_authenticator()
    }

    /// Returns the resumption PSK secret of the current epoch.
    pub fn resumption_psk_secret(&self) -> &ResumptionPskSecret {
        self.group_epoch_secrets().resumption_psk()
    }

    /// Returns a resumption psk for a given epoch. If no resumption psk
    /// is available for that epoch,  `None` is returned.
    pub fn get_past_resumption_psk(&self, epoch: GroupEpoch) -> Option<&ResumptionPskSecret> {
        self.resumption_psk_store.get(epoch)
    }

    /// Export a group info object for this group.
    pub fn export_group_info<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<MlsMessageOut, ExportGroupInfoError> {
        self.export_group_info_with_additional_extensions(crypto, signer, with_ratchet_tree, None)
    }

    /// Export a group info object for this group, with additional extensions.
    ///
    ///  Returns an error if a  [`RatchetTreeExtension`] or [`ExternalPubExtension`] is added
    ///  directly here.
    pub fn export_group_info_with_additional_extensions<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
        additional_extensions: impl IntoIterator<Item = Extension>,
    ) -> Result<MlsMessageOut, ExportGroupInfoError> {
        let extensions = {
            let ratchet_tree_extension = || {
                Extension::RatchetTree(RatchetTreeExtension::new(
                    self.public_group().export_ratchet_tree(),
                ))
            };

            let external_pub_extension = || -> Result<Extension, ExportGroupInfoError> {
                let external_pub = self
                    .group_epoch_secrets()
                    .external_secret()
                    .derive_external_keypair(crypto, self.ciphersuite())
                    .map_err(LibraryError::unexpected_crypto_error)?
                    .public;
                Ok(Extension::ExternalPub(ExternalPubExtension::new(
                    HpkePublicKey::from(external_pub),
                )))
            };

            let mut extensions = if with_ratchet_tree {
                vec![ratchet_tree_extension(), external_pub_extension()?]
            } else {
                vec![external_pub_extension()?]
            };

            extensions.extend(
                additional_extensions
                    .into_iter()
                    .map(|extension| {
                        if extension.as_ratchet_tree_extension().is_ok()
                            || extension.as_external_pub_extension().is_ok()
                        {
                            Err(InvalidExtensionError::CannotAddDirectlyToGroupInfo)
                        } else {
                            Ok(extension)
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            Extensions::from_vec(extensions)?
        };

        // Create to-be-signed group info.
        let group_info_tbs = GroupInfoTBS::new(
            self.context().clone(),
            extensions,
            self.message_secrets()
                .confirmation_key()
                .tag(
                    crypto,
                    self.ciphersuite(),
                    self.context().confirmed_transcript_hash(),
                )
                .map_err(LibraryError::unexpected_crypto_error)?,
            self.own_leaf_index(),
        )?;

        // Sign to-be-signed group info.
        let group_info = group_info_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;
        Ok(group_info.into())
    }
}
