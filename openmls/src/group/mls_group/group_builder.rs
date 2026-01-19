//! Building a group from a welcome message.

use crate::{
    ciphersuite::Secret,
    group::{
        creation::{decrypt_group_secrets, keys_for_welcome, prepare_key_schedule},
        MlsGroupJoinConfig, ProcessedWelcome, WelcomeError,
    },
    messages::Welcome,
    prelude::{GroupSecrets, KeyPackageBundle},
    schedule::{
        psk::{load_psks, store::ResumptionPskStore},
        PreSharedKeyId, ResumptionPskSecret,
    },
    storage::{OpenMlsProvider, StorageProvider},
    treesync::RatchetTreeIn,
};

/// Join a group with the [`GroupBuilder`].
///
/// Usage:
/// 1. `GroupBuilder::new(config, welcome)`
/// 2. Add state `with_ratchet_tree`, `with_resumption_psk`
/// 3. Read the key package for decryption `read_key_package`
/// 4. Decrypt the group secrets with it `decrypt_group_secrets`
/// 5. Read the PSKs for decryption `read_psks`
/// 6. Compute the new key schedule `key_schedule`
/// 7. Generate the staged commit `into_staged_welcome`
/// 8. Build the group `into_group`
pub struct GroupBuilder<Stage> {
    /// The current stage
    stage: Stage,
}

/// The initial builder state
pub struct Init<'a> {
    /// The config.
    config: &'a MlsGroupJoinConfig,

    /// The Welcome message.
    welcome: Welcome,

    /// Optionally: a separate ratchet tree.
    ratchet_tree: Option<RatchetTreeIn>,

    /// Optionally: a resumption PSK secret.
    resumption_psk_secret: Option<ResumptionPskSecret>,
}

/// State after reading the key package bundle for decrypting the welcome
/// message from storage.
pub struct KeyPackageState<'a> {
    /// The initial state.
    init: Init<'a>,

    /// The bundle used for decrypting this welcome.
    key_package_bundle: KeyPackageBundle,
}

/// The state after decrypting the group secrets in the welcome message.
pub struct Decrypted<'a> {
    /// The initial state.
    key_package: KeyPackageState<'a>,

    /// The decrypted group secrets.
    group_secrets: GroupSecrets,
}

/// The state after loading and generating the PSK secret.
pub struct Psks<'a> {
    /// The initial state.
    decrypted: Decrypted<'a>,

    /// Loaded PSKs.
    psks: Vec<(PreSharedKeyId, Secret)>,

    /// The resumption PSK store.
    resumption_psk_store: ResumptionPskStore,
}

impl<'a> GroupBuilder<Init<'a>> {
    /// Build a new group from an incoming [`Welcome`] message and with the
    /// given [`MlsGroupJoinConfig`].
    pub fn new(config: &'a MlsGroupJoinConfig, welcome: Welcome) -> Self {
        Self {
            stage: Init {
                config,
                welcome,
                ratchet_tree: None,
                resumption_psk_secret: None,
            },
        }
    }

    /// Set the ratchet tree.
    pub fn with_ratchet_tree(mut self, ratchet_tree: RatchetTreeIn) -> Self {
        self.stage.ratchet_tree = Some(ratchet_tree);
        self
    }

    /// Set the resumption PSK secret.
    /// The caller must provide the epoch this PSK secret is from.
    pub fn with_resumption_psk(mut self, resumption_psk_secret: ResumptionPskSecret) -> Self {
        self.stage.resumption_psk_secret = Some(resumption_psk_secret);
        self
    }

    /// Read the key package from storage
    pub fn read_key_package<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<GroupBuilder<KeyPackageState<'a>>, WelcomeError<Provider::StorageError>> {
        let key_package_bundle = keys_for_welcome(&self.stage.welcome, provider)?;

        Ok(GroupBuilder {
            stage: KeyPackageState {
                init: self.stage,
                key_package_bundle,
            },
        })
    }
}

impl<'a> GroupBuilder<KeyPackageState<'a>> {
    /// Decrypt the welcome message and return the next stage.
    pub fn decrypt_group_secrets<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        // XXX: Storage not needed here, but for the error.
    ) -> Result<GroupBuilder<Decrypted<'a>>, WelcomeError<Provider::StorageError>> {
        let group_secrets = decrypt_group_secrets(
            provider.crypto(),
            &self.stage.init.welcome,
            &self.stage.key_package_bundle,
        )?;

        Ok(GroupBuilder {
            stage: Decrypted {
                key_package: self.stage,
                group_secrets,
            },
        })
    }
}

impl<'a> GroupBuilder<Decrypted<'a>> {
    /// Load PSKs required for the welcome message.
    pub fn read_psks<Provider: StorageProvider>(
        mut self,
        provider: &Provider,
    ) -> Result<GroupBuilder<Psks<'a>>, WelcomeError<Provider::Error>> {
        let mut resumption_psk_store =
            ResumptionPskStore::new(self.stage.key_package.init.config.number_of_resumption_psks);
        if let Some(psk) = self.stage.key_package.init.resumption_psk_secret.take() {
            resumption_psk_store.add(0.into(), psk);
        }

        let psks = load_psks(
            provider,
            &resumption_psk_store,
            &self.stage.group_secrets.psks,
        )?
        .into_iter()
        .map(|(id, s)| (id.clone(), s))
        .collect();

        Ok(GroupBuilder {
            stage: Psks {
                decrypted: self.stage,
                psks,
                resumption_psk_store,
            },
        })
    }
}

impl<'a> GroupBuilder<Psks<'a>> {
    /// Build the key schedule and the processed welcome
    pub fn key_schedule<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        // XXX: Storage not needed here, but for the error.
    ) -> Result<ProcessedWelcome, WelcomeError<Provider::StorageError>> {
        let ciphersuite = self.stage.decrypted.key_package.init.welcome.ciphersuite();
        let (key_schedule, verifiable_group_info) = prepare_key_schedule(
            provider.crypto(),
            self.stage.decrypted.key_package.init.welcome,
            &self.stage.decrypted.key_package.key_package_bundle,
            &self.stage.decrypted.group_secrets,
            ciphersuite,
            self.stage.psks,
        )?;

        Ok(ProcessedWelcome {
            mls_group_config: self.stage.decrypted.key_package.init.config.clone(),
            ciphersuite,
            group_secrets: self.stage.decrypted.group_secrets,
            key_schedule,
            verifiable_group_info,
            resumption_psk_store: self.stage.resumption_psk_store,
            key_package_bundle: self.stage.decrypted.key_package.key_package_bundle,
        })
    }
}
