use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    storage::{self, CURRENT_VERSION},
    types::Ciphersuite,
    OpenMlsProvider,
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, SerializeBytes, TlsSerialize, TlsSize, VLBytes};

use crate::{
    ciphersuite::{hash_ref::HashReference, hpke, AeadKey, AeadNonce, Mac, Secret},
    error::LibraryError,
    group::{CreateCommitError, WelcomeError, WelcomeKeyMaterial},
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{
        group_info::{GroupInfo, GroupInfoTBS, VerifiableGroupInfo},
        ConfirmationTag, GroupSecrets, GroupSecretsError, PathSecret, Welcome,
    },
    schedule::{
        errors::{KeyScheduleError, PskError},
        psk::{load_psks, store::ResumptionPskStore, PreSharedKeyId, PskSecret},
        JoinerSecret, KeySchedule, Psk, WelcomeSecret,
    },
    storage::StorageProvider,
    test_utils::frankenstein::{
        group_info::FrankenGroupInfo, key_package, FrankenEncryptedGroupSecrets,
        FrankenGroupSecrets, FrankenKeyPackage, FrankenPathSecret, FrankenWelcome,
    },
};

use super::FrankenAuthenticatedContentTbm;

/// Computes a valid membership tag for the provided content.
pub fn compute_membership_tag(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    membership_key: &[u8],
    auth_content_tbm: &FrankenAuthenticatedContentTbm,
) -> VLBytes {
    let serialized_auth_content_tbm = &auth_content_tbm.tls_serialize_detached().unwrap();
    crypto
        .hmac(
            ciphersuite.hash_algorithm(),
            membership_key,              // Extract salt is HMAC key
            serialized_auth_content_tbm, // Extract ikm is HMAC message
        )
        .unwrap()
        .as_slice()
        .into()
}

/// Implements the "sign with label" function of the spec.
pub fn sign_with_label(signer: &impl Signer, label: &[u8], msg: &[u8]) -> Vec<u8> {
    let data = FrankenSignContent::new(label, msg)
        .tls_serialize_detached()
        .unwrap();
    signer.sign(&data).unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsSize)]
pub struct FrankenSignContent<'a> {
    label: Vec<u8>,
    content: &'a [u8],
}

impl<'a> FrankenSignContent<'a> {
    pub fn new(label: &[u8], content: &'a [u8]) -> Self {
        let mut tagged_label = b"MLS 1.0 ".to_vec();
        tagged_label.extend_from_slice(label);

        Self {
            label: tagged_label,
            content,
        }
    }
}

impl FrankenWelcome {
    /// Decrypts a [`FrankenWelcome`] using the first group secret decryptable by `storage`.
    /// Performs no semantic checks.
    ///
    /// This method is meant for tests that need to manipulate the encrypted contents.
    pub fn open<Crypto, Storage>(
        &self,
        crypto: &Crypto,
        storage: &Storage,
    ) -> Result<(Ciphersuite, FrankenGroupSecrets, FrankenGroupInfo), WelcomeError<Storage::Error>>
    where
        Crypto: OpenMlsCrypto,
        Storage: StorageProvider,
    {
        // Implementation is roughly inspired by [`mls_group::creation::decrypt_group_secrets`], without validity checks.
        let ciphersuite = Ciphersuite::try_from(self.cipher_suite)
            .expect("cannot open welcome with invalid ciphersuite");
        crypto
            .supports(ciphersuite)
            .map_err(|_| WelcomeError::UnsupportedCiphersuite(ciphersuite))?;

        // Find and decrypt GroupSecrets addressed to us
        let (key_material, egs) = self.find_decryptable_secret(storage)?;
        let group_secrets_plaintext = hpke::decrypt_with_label(
            key_material.init_private_key(),
            "Welcome",
            self.encrypted_group_info.as_slice(),
            &egs.encrypted_group_secrets.clone().into(),
            ciphersuite,
            crypto,
        )
        .map_err(|_| GroupSecretsError::DecryptionFailed)?;
        let group_secrets = FrankenGroupSecrets::tls_deserialize_exact(group_secrets_plaintext)
            .map_err(|_| GroupSecretsError::Malformed)?;

        // Derive keys for GroupInfo
        let (welcome_key, welcome_nonce) = group_secrets.welcome_keys(
            ciphersuite,
            group_secrets.psk_secret(ciphersuite, crypto, storage)?,
            crypto,
        )?;

        // Decrypt GroupInfo
        let group_info: GroupInfo = VerifiableGroupInfo::try_from_ciphertext(
            &welcome_key,
            &welcome_nonce,
            self.encrypted_group_info.as_slice(),
            &[],
            crypto,
        )?
        .into();

        Ok((ciphersuite, group_secrets, group_info.into()))
    }

    /// Signs and encrypts a new [`FrankenWelcome`] message from components.
    /// Performs no semantic checks.
    ///
    /// This method is meant for tests that need to manipulate the encrypted contents.
    pub fn seal<Crypto, Storage>(
        ciphersuite: Ciphersuite,
        group_secrets: &FrankenGroupSecrets,
        group_info: &FrankenGroupInfo,
        signer: &impl Signer,
        invited_members: &[(FrankenKeyPackage, Option<FrankenPathSecret>)],
        crypto: &Crypto,
        storage: &Storage,
    ) -> Result<Self, CreateCommitError>
    where
        Crypto: OpenMlsCrypto,
        Storage: StorageProvider,
    {
        // Sign updated group info
        let mut group_info = group_info.clone();
        group_info.resign(signer);

        // Seal GroupInfo
        let psk_secret = group_secrets.psk_secret(ciphersuite, crypto, storage)?;
        let (welcome_key, welcome_nonce) =
            group_secrets.welcome_keys(ciphersuite, psk_secret, crypto)?;
        let encrypted_group_info = welcome_key
            .aead_seal(
                crypto,
                group_info
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?
                    .as_slice(),
                &[],
                &welcome_nonce,
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Encrypt GroupSecrets for each invited member
        let psk_ids = group_secrets.psk_ids();
        let joiner_secret = group_secrets.joiner_secret.clone().into();
        let encrypted_group_secrets: Vec<FrankenEncryptedGroupSecrets> = invited_members
            .iter()
            .map(|invited_member| {
                let (invited_key_package, path_secret) = invited_member;

                let path_secret = path_secret.as_ref().map(|path_secret| PathSecret {
                    path_secret: Secret::from_slice(path_secret.as_slice()),
                });
                let encoded_group_secrets =
                    GroupSecrets::new_encoded(&joiner_secret, path_secret.as_ref(), &psk_ids)
                        .unwrap();

                let key_package: KeyPackage = invited_key_package.clone().into();
                let ciphertext = hpke::encrypt_with_label(
                    key_package.hpke_init_key().as_slice(),
                    "Welcome",
                    encrypted_group_info.as_slice(),
                    &encoded_group_secrets,
                    key_package.ciphersuite(),
                    crypto,
                )
                .unwrap();

                FrankenEncryptedGroupSecrets {
                    new_member: key_package.hash_ref(crypto).unwrap().as_slice().into(),
                    encrypted_group_secrets: ciphertext.into(),
                }
            })
            .collect();

        // create Welcome message
        Ok(Self {
            cipher_suite: ciphersuite.into(),
            secrets: encrypted_group_secrets,
            encrypted_group_info: encrypted_group_info.into(),
        })
    }

    /// Finds the first `EncryptedGroupSecret` in this `Welcome` that corresponds to a `KeyPackageBundle` in `storage`.
    ///
    /// Combines [`crate::group::mls_group::creation::keys_for_welcome`] and [`Welcome::find_encrypted_group_secret`]
    pub(crate) fn find_decryptable_secret<Storage>(
        &self,
        storage: &Storage,
    ) -> Result<(WelcomeKeyMaterial, &FrankenEncryptedGroupSecrets), WelcomeError<Storage::Error>>
    where
        Storage: StorageProvider,
    {
        // Store all secrets for reasonable tests
        for egs in self.secrets.as_slice() {
            let hash_ref = &HashReference::from_slice(egs.new_member.as_slice());
            if let Some(key_package_bundle) = storage
                .key_package(hash_ref)
                .map_err(WelcomeError::StorageError)?
            {
                return Ok((
                    WelcomeKeyMaterial::with_key_package_bundle(key_package_bundle),
                    egs,
                ));
            }
        }
        Err(WelcomeError::NoMatchingKeyPackage)
    }

    /// Create a FrankenWelcome from `self` with updated, sealed content.
    ///
    /// Equivalent to using [`Self::open`] and [`Self::seal`].
    pub fn with_sealed_update<F, InvitedProvider>(
        &self,
        signer: &impl Signer,
        signer_provider: &impl OpenMlsProvider,
        invited_key_package: &KeyPackage,
        invited_provider: &InvitedProvider,
        f: F,
    ) -> Self
    where
        F: FnOnce(&mut Ciphersuite, &mut FrankenGroupSecrets, &mut FrankenGroupInfo),
        InvitedProvider: OpenMlsProvider,
    {
        let (mut ciphersuite, mut group_secrets, mut group_info) = self
            .open(invited_provider.crypto(), invited_provider.storage())
            .expect("failed to open FrankenWelcome");

        f(&mut ciphersuite, &mut group_secrets, &mut group_info);

        FrankenWelcome::seal(
            ciphersuite,
            &group_secrets,
            &group_info,
            signer,
            &[(
                invited_key_package.clone().into(),
                group_secrets.path_secret.clone(),
            )],
            signer_provider.crypto(),
            signer_provider.storage(),
        )
        .expect("failed to seal FrankenWelcome")
    }
}

impl FrankenGroupSecrets {
    pub fn psk_ids(&self) -> Vec<PreSharedKeyId> {
        self.psks.iter().clone().map(Into::into).collect()
    }

    pub fn psk_secret<Crypto, Storage>(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &Crypto,
        storage: &Storage,
    ) -> Result<PskSecret, PskError>
    where
        Crypto: OpenMlsCrypto,
        Storage: StorageProvider,
    {
        let psk_ids = self.psk_ids();
        let psks = load_psks(
            storage,
            // No resumption keys for now
            &ResumptionPskStore::new(0),
            psk_ids.as_slice(),
        )?;
        let psk_secret = PskSecret::new(crypto, ciphersuite, psks)?;
        Ok(psk_secret)
    }

    pub(crate) fn welcome_keys<Crypto>(
        &self,
        ciphersuite: Ciphersuite,
        psk_secret: PskSecret,
        crypto: &Crypto,
    ) -> Result<(AeadKey, AeadNonce), LibraryError>
    where
        Crypto: OpenMlsCrypto,
    {
        let joiner_secret = self.joiner_secret.clone().into();
        let key_schedule = KeySchedule::init(ciphersuite, crypto, &joiner_secret, psk_secret)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let welcome_secret = key_schedule.welcome(crypto, ciphersuite).unwrap();
        let (welcome_key, welcome_nonce) = welcome_secret
            .derive_welcome_key_nonce(crypto, ciphersuite)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok((welcome_key, welcome_nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::FrankenExtension, *};
    use crate::group::{
        mls_group::tests_and_kats::utils::{setup_alice_group, setup_client},
        StagedWelcome,
    };

    #[openmls_test::openmls_test]
    fn test_reseal_franken_group_info() {
        // create Welcome message and GroupInfo
        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
            setup_alice_group(ciphersuite, alice_provider);

        let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
            setup_client("Bob", ciphersuite, bob_provider);
        let message_bundle = alice_group
            .commit_builder()
            .propose_adds([bob_kpb.key_package.clone()])
            .load_psks(alice_provider.storage())
            .unwrap()
            .use_ratchet_tree_extension(true)
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_proposal| true,
            )
            .unwrap()
            .stage_commit(alice_provider)
            .unwrap();

        // Open, modify and re-seal Welcome
        let welcome: FrankenWelcome = message_bundle.welcome().unwrap().clone().into();
        let opened = welcome.open(bob_provider.crypto(), bob_provider.storage());
        let (_ciphersuite, group_secrets, mut group_info) = opened.unwrap();

        group_info.extensions.push(FrankenExtension::Unknown(
            0xf000,
            b"Test extension modifying group_info".into(),
        ));

        let resealed = FrankenWelcome::seal(
            ciphersuite,
            &group_secrets,
            &group_info,
            &alice_signer,
            &[(
                bob_kpb.key_package.clone().into(),
                group_secrets.path_secret.clone(),
            )],
            alice_provider.crypto(),
            alice_provider.storage(),
        );

        // validate Welcome message
        let staged_welcome = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            resealed.unwrap().into(),
            None,
        )
        .expect("expected valid join from unmodified welcome");

        let _bob_group = staged_welcome
            .into_group(bob_provider)
            .expect("expected valid group from join");
    }

    #[openmls_test::openmls_test]
    fn test_reseal_helper_franken_group_info() {
        // create Welcome message and GroupInfo
        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let (mut alice_group, _alice_credential, alice_signer, _alice_pk) =
            setup_alice_group(ciphersuite, alice_provider);

        let (_bob_credential, bob_kpb, _bob_signer, _bob_pk) =
            setup_client("Bob", ciphersuite, bob_provider);
        let message_bundle = alice_group
            .commit_builder()
            .propose_adds([bob_kpb.key_package.clone()])
            .load_psks(alice_provider.storage())
            .unwrap()
            .use_ratchet_tree_extension(true)
            .build(
                alice_provider.rand(),
                alice_provider.crypto(),
                &alice_signer,
                |_proposal| true,
            )
            .unwrap()
            .stage_commit(alice_provider)
            .unwrap();

        // Open, modify and re-seal Welcome
        let welcome: FrankenWelcome = message_bundle.welcome().unwrap().clone().into();
        let welcome = welcome.with_sealed_update(
            &alice_signer,
            alice_provider,
            &bob_kpb.key_package,
            bob_provider,
            |_, _, group_info| {
                group_info.extensions.push(FrankenExtension::Unknown(
                    0xf000,
                    b"Test extension modifying group_info".into(),
                ));
            },
        );

        // validate Welcome message
        let staged_welcome = StagedWelcome::new_from_welcome(
            bob_provider,
            alice_group.configuration(),
            welcome.into(),
            None,
        )
        .expect("expected valid join from unmodified welcome");

        let _bob_group = staged_welcome
            .into_group(bob_provider)
            .expect("expected valid group from join");
    }
}
