use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::BasicCredential as BasicCredentialKeys;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{signatures::Signer, OpenMlsCryptoProvider};

pub struct Identity {
    pub(crate) kp: KeyPackage,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: Box<dyn Signer>,
}

impl Identity {
    pub(crate) fn new(ciphersuite: Ciphersuite, crypto: &OpenMlsRustCrypto, id: &[u8]) -> Self {
        let credential = Credential::new(id.to_vec(), CredentialType::Basic).unwrap();
        let signature_keys =
            BasicCredentialKeys::new(ciphersuite.signature_algorithm(), crypto.crypto()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signature_keys.to_public_vec().into(),
        };
        signature_keys.store(crypto.key_store()).unwrap();

        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                crypto,
                &signature_keys,
                credential_with_key.clone(),
            )
            .unwrap();

        Self {
            kp: key_package,
            credential_with_key,
            signer: Box::new(signature_keys),
        }
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.identity()
    }
}
