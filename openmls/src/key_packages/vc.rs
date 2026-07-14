//! Key package facilities for virtual clients

use openmls_traits::{
    crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider, types::Ciphersuite,
    OpenMlsProvider,
};
use tls_codec::Serialize;

use crate::{
    binary_tree::LeafNodeIndex,
    components::{
        vc_derivation_info::{
            load_vc_epoch_state_and_tree, merge_vc_derivation_info, resolve_vc_leaf_dictionary,
            DerivationInfo, DerivationInfoTbe, EpochEncryptionKey, EpochId, KeyPackageInfo,
            OperationSecret, VirtualClientOperationType, VirtualClientsError,
        },
        vc_operation_tree::OperationSecretTree,
    },
    credentials::CredentialWithKey,
    extensions::AppDataDictionary,
    key_packages::{
        errors::KeyPackageNewError, KeyPackage, KeyPackageBuilder, KeyPackageBundle,
        KeyPackageLeafNodeParams,
    },
};

/// A batch of virtual-client KeyPackages a sibling can reproduce.
///
/// Build from a single epoch id and generation.
#[derive(Debug)]
pub struct VcKeyPackageBatch {
    /// The `key_package` operation generation consumed for the whole batch.
    pub generation: u32,
    /// One entry per KeyPackage built, in batch-index order. Never empty.
    pub key_packages: Vec<(
        KeyPackageBundle,
        crate::components::vc_derivation_info::KeyPackageInfo,
    )>,
}

/// A builder for a batch of virtual-client KeyPackages a sibling can reproduce.
///
/// Allows to build heterogeneous batch of key packages, e.g. non-last-resort and last-restort, or
/// packages with different ciphersuits. Return the batch on [`Self::finalize`]. Dropping the
/// builder without calling `finalize` burns no generation.
#[derive(Debug)]
pub struct VcKeyPackageBatchBuilder {
    epoch_id: EpochId,
    /// Ciphersuite of the emulation group
    emulation_ciphersuite: Ciphersuite,
    epoch_encryption_key: EpochEncryptionKey,
    emulation_leaf_index: LeafNodeIndex,
    generation: u32,
    operation_secret: OperationSecret,
    /// Advanced in memory by new()
    ///
    /// Only persisted in finalize(), so dropped builder burns not generation.
    operation_tree: OperationSecretTree,
    key_packages: Vec<(KeyPackageBundle, KeyPackageInfo)>,
}

impl VcKeyPackageBatchBuilder {
    /// Load emulation epoch and allocate the next generation of the key package operation ratchet.
    ///
    /// Nothing is persisted yet. Dropping the builder without calling `finalize` burns no
    /// generation.
    pub fn new(
        provider: &impl OpenMlsProvider,
        epoch_id: EpochId,
    ) -> Result<Self, KeyPackageNewError> {
        Self::with_capacity(provider, epoch_id, 0)
    }

    /// Same as [`Self::new`], but with a capacity hint for the number of key packages.
    pub fn with_capacity(
        provider: &impl OpenMlsProvider,
        epoch_id: EpochId,
        capacity: usize,
    ) -> Result<Self, KeyPackageNewError> {
        let (state, mut operation_tree) = load_vc_epoch_state_and_tree(provider, &epoch_id)?;
        let (emulation_leaf_index, epoch_encryption_key, emulation_ciphersuite) =
            state.into_parts();
        let (generation, operation_secret) = operation_tree.next_operation_secret(
            provider.crypto(),
            emulation_ciphersuite,
            &epoch_id,
            emulation_leaf_index,
            VirtualClientOperationType::KeyPackage,
            b"",
        )?;
        Ok(Self {
            epoch_id,
            emulation_ciphersuite,
            epoch_encryption_key,
            emulation_leaf_index,
            generation,
            operation_secret,
            operation_tree,
            key_packages: Vec::with_capacity(capacity),
        })
    }

    /// Build one key package at the next index.
    ///
    /// The key package builder carries the per-step config: key package extensions (incl. last
    /// resort), leaf node extensions, capabilities, lifetime.
    ///
    /// If building fails, the builder is left in a valid state:
    ///
    /// - No storage is touched
    /// - No generation is burned
    /// - The failed index isn't consumed
    pub fn add_key_package(
        &mut self,
        builder: KeyPackageBuilder,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
    ) -> Result<&KeyPackageInfo, KeyPackageNewError> {
        if ciphersuite.signature_algorithm() != signer.signature_scheme() {
            return Err(KeyPackageNewError::CiphersuiteSignatureSchemeMismatch);
        }

        // Resolve and validate the leaf configuration
        let resolved_dictionary = resolve_vc_leaf_dictionary(
            builder.leaf_node_capabilities.as_ref(),
            builder.leaf_node_extensions.as_ref(),
            None,
        )?;

        let key_package_index = self.key_packages.len() as u32;
        self.key_packages.push(self.build_vc_key_package_for_index(
            builder,
            ciphersuite,
            crypto,
            signer,
            credential_with_key,
            &resolved_dictionary,
            key_package_index,
        )?);

        let (_, info) = self.key_packages.last().expect("logic error: just pushed");
        Ok(info)
    }

    /// Finalize the batch.
    ///
    /// Persists the operation tree and the key packages. The operation is not atomic. On failure,
    /// the generation should be considered as burned. Few orphaned key packages may be left in
    /// storage.
    pub fn finalize(
        self,
        provider: &impl OpenMlsProvider,
    ) -> Result<VcKeyPackageBatch, KeyPackageNewError> {
        if self.key_packages.is_empty() {
            return Err(KeyPackageNewError::EmptyBatch);
        }

        // Persist the advanced operation tree before the KeyPackages it backs.
        // If a KeyPackage write fails after this, the burned generation is
        // harmless, but writing KeyPackages first would let the next batch
        // reuse the same key material under an unconsumed generation.
        provider
            .storage()
            .write_vc_operation_tree(&self.epoch_id, &self.operation_tree)
            .map_err(|e| {
                log::error!("vc: persist advanced operation tree in build_vc_batch failed: {e:?}");
                VirtualClientsError::StorageError
            })?;
        for (full_kp, info) in &self.key_packages {
            provider
                .storage()
                .write_key_package(&info.key_package_ref, full_kp)
                .map_err(|_| KeyPackageNewError::StorageError)?;
        }

        Ok(VcKeyPackageBatch {
            generation: self.generation,
            key_packages: self.key_packages,
        })
    }

    /// Derive and build a single KeyPackage at `key_package_index`
    #[expect(clippy::too_many_arguments)]
    fn build_vc_key_package_for_index(
        &self,
        mut builder: KeyPackageBuilder,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        resolved_dictionary: &AppDataDictionary,
        key_package_index: u32,
    ) -> Result<(KeyPackageBundle, KeyPackageInfo), KeyPackageNewError> {
        // Derive the per-index seed and the init and leaf encryption key
        // secrets under the emulation ciphersuite. Only the final DeriveKeyPair
        // uses the KeyPackage's own ciphersuite.
        let seed = self.operation_secret.derive_key_package_seed_secret(
            crypto,
            self.emulation_ciphersuite,
            key_package_index,
        )?;
        let init_key_pair = seed
            .derive_init_key_secret(crypto, self.emulation_ciphersuite)?
            .generate_init_key_pair(crypto, ciphersuite)?;
        let encryption_key_pair = seed
            .derive_encryption_key_secret(crypto, self.emulation_ciphersuite)?
            .generate_encryption_key_pair(crypto, ciphersuite)?;

        // Wrap the TBE bound to the new leaf via its serialized encryption key.
        // The leaf dictionary was resolved and validated once for the whole
        // batch, so reuse a clone here.
        let leaf_encryption_key = encryption_key_pair
            .public_key()
            .tls_serialize_detached()
            .map_err(VirtualClientsError::from)?;
        let tbe = DerivationInfoTbe::KeyPackage {
            leaf_index: self.emulation_leaf_index,
            generation: self.generation,
            key_package_index,
        };
        let derivation_info = DerivationInfo::encrypt(
            crypto,
            self.emulation_ciphersuite,
            &self.epoch_encryption_key,
            self.epoch_id.clone(),
            &leaf_encryption_key,
            &tbe,
        )?;
        let derivation_info_bytes = derivation_info
            .tls_serialize_detached()
            .map_err(VirtualClientsError::from)?;
        builder.ensure_last_resort();
        let leaf_node_extensions = merge_vc_derivation_info(
            builder.leaf_node_extensions.as_ref(),
            resolved_dictionary.clone(),
            derivation_info_bytes,
        )
        .map_err(KeyPackageNewError::LibraryError)?;

        let leaf_node_params = KeyPackageLeafNodeParams {
            lifetime: builder.key_package_lifetime.unwrap_or_default(),
            capabilities: builder.leaf_node_capabilities.unwrap_or_default(),
            extensions: leaf_node_extensions,
        };
        let (key_package, encryption_key_pair) = KeyPackage::new_from_vc_keys(
            ciphersuite,
            signer,
            credential_with_key,
            builder.key_package_extensions.unwrap_or_default(),
            leaf_node_params,
            init_key_pair.public.into(),
            encryption_key_pair,
        )?;

        let key_package_ref = key_package.hash_ref(crypto)?;
        let full_kp = KeyPackageBundle {
            key_package,
            private_init_key: init_key_pair.private,
            private_encryption_key: encryption_key_pair.private_key().clone(),
        };

        Ok((
            full_kp,
            KeyPackageInfo {
                key_package_ref,
                key_package_index,
            },
        ))
    }
}
