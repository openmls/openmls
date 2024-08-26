use errors::{ExportGroupInfoError, ExportSecretError};
use openmls_traits::signatures::Signer;

use crate::{
    ciphersuite::HpkePublicKey,
    schedule::{EpochAuthenticator, ResumptionPskSecret},
    storage::OpenMlsProvider,
};

use super::*;

impl MlsGroup {
    // === Export secrets ===

    /// Exports a secret from the current epoch.
    /// Returns [`ExportSecretError::KeyLengthTooLong`] if the requested
    /// key length is too long.
    /// Returns [`ExportSecretError::GroupStateError(MlsGroupStateError::UseAfterEviction)`](MlsGroupStateError::UseAfterEviction)
    /// if the group is not active.
    pub fn export_secret<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExportSecretError> {
        let crypto = provider.crypto();

        if key_length > u16::MAX.into() {
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
    pub fn export_group_info<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        signer: &impl Signer,
        with_ratchet_tree: bool,
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
                    .derive_external_keypair(provider.crypto(), self.ciphersuite())
                    .map_err(LibraryError::unexpected_crypto_error)?
                    .public;
                Ok(Extension::ExternalPub(ExternalPubExtension::new(
                    HpkePublicKey::from(external_pub),
                )))
            };

            if with_ratchet_tree {
                Extensions::from_vec(vec![ratchet_tree_extension(), external_pub_extension()?])
                    .map_err(|_| {
                        LibraryError::custom(
                            "There should not have been duplicate extensions here.",
                        )
                    })?
            } else {
                Extensions::single(external_pub_extension()?)
            }
        };

        // Create to-be-signed group info.
        let group_info_tbs = GroupInfoTBS::new(
            self.context().clone(),
            extensions,
            self.message_secrets()
                .confirmation_key()
                .tag(
                    provider.crypto(),
                    self.ciphersuite(),
                    self.context().confirmed_transcript_hash(),
                )
                .map_err(LibraryError::unexpected_crypto_error)?,
            self.own_leaf_index(),
        );

        // Sign to-be-signed group info.
        let group_info = group_info_tbs
            .sign(signer)
            .map_err(|_| LibraryError::custom("Signing failed"))?;
        Ok(group_info.into())
    }
}
