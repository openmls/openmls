use openmls_traits::{
    crypto::OpenMlsCrypto, signatures::Signer, storage::CURRENT_VERSION, types::Ciphersuite,
    OpenMlsProvider,
};
use tls_codec::{Deserialize, Serialize, SerializeBytes, TlsSerialize, TlsSize, VLBytes};

use crate::{
    ciphersuite::{hash_ref::HashReference, hpke},
    group::{WelcomeError, WelcomeKeyMaterial},
    key_packages::KeyPackageBundle,
    messages::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        GroupSecretsError,
    },
    schedule::{
        psk::{load_psks, store::ResumptionPskStore, PreSharedKeyId, PskSecret},
        JoinerSecret, KeySchedule,
    },
    storage::StorageProvider,
    test_utils::frankenstein::{
        group_info::FrankenGroupInfo, FrankenEncryptedGroupSecrets, FrankenGroupSecrets,
        FrankenWelcome,
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
    /// Like [`mls_group::creation::decrypt_group_secrets`]
    pub fn open<Crypto, Storage>(
        &self,
        crypto: &Crypto,
        storage: &Storage,
    ) -> Result<
        (Ciphersuite, FrankenGroupSecrets, FrankenGroupInfo),
        WelcomeError<<Storage as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::Error>,
    >
    where
        Crypto: OpenMlsCrypto,
        Storage: StorageProvider,
    {
        let ciphersuite = Ciphersuite::try_from(self.cipher_suite)
            .expect("cannot open welcome with invalid ciphersuite");
        crypto
            .supports(ciphersuite)
            .map_err(|_| WelcomeError::UnsupportedCiphersuite(ciphersuite))?;

        // keys_for_welcome
        let (resumption_psk_store, key_material, egs) = self.keys(storage)?;

        // Like GroupSecrets::try_from_ciphertext
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

        // Like finish_processed_welcome, without resumption for now
        let psk_secret = {
            let psk_ids: Vec<PreSharedKeyId> = group_secrets
                .psks
                .iter()
                .clone()
                .map(|franken_psk_id| franken_psk_id.into()) // Replace with method identifier
                .collect();

            let psks = load_psks(storage, &resumption_psk_store, &psk_ids)?;

            PskSecret::new(crypto, ciphersuite, psks)?
        };

        let joiner_secret = group_secrets.joiner_secret.clone().into();
        let key_schedule = KeySchedule::init(ciphersuite, crypto, &joiner_secret, psk_secret)?;

        // derive the keys for decrypting the group info
        let (welcome_key, welcome_nonce) = key_schedule
            .welcome(crypto, ciphersuite)
            .unwrap()
            .derive_welcome_key_nonce(crypto, ciphersuite)
            .unwrap();

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

    // Like keys_for_welcome + find_encrypted_group_secret
    pub(crate) fn keys<Storage>(
        &self,
        storage: &Storage,
    ) -> Result<
        (
            ResumptionPskStore,
            WelcomeKeyMaterial,
            &FrankenEncryptedGroupSecrets,
        ),
        WelcomeError<Storage::Error>,
    >
    where
        Storage: StorageProvider,
    {
        // Store all secrets for reasonable tests
        let resumption_psk_store = ResumptionPskStore::new(0x1000);

        for egs in self.secrets.as_slice() {
            let hash_ref = &HashReference::from_slice(egs.new_member.as_slice());
            if let Some(key_package_bundle) = storage
                .key_package(hash_ref)
                .map_err(WelcomeError::StorageError)?
            {
                return Ok((
                    resumption_psk_store,
                    WelcomeKeyMaterial::with_key_package_bundle(key_package_bundle),
                    egs,
                ));
            }
        }
        Err(WelcomeError::NoMatchingKeyPackage)
    }
}
