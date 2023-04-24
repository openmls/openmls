use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::OpenMlsBasicCredential;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

pub struct Identity {
    pub(crate) kp: KeyPackage,
    pub(crate) credential: OpenMlsBasicCredential,
}

impl Identity {
    pub(crate) fn new(ciphersuite: Ciphersuite, crypto: &OpenMlsRustCrypto, id: &[u8]) -> Self {
        let credential =
            OpenMlsBasicCredential::new(ciphersuite.signature_algorithm(), id.to_vec()).unwrap();
        credential.store(crypto.key_store()).unwrap();

        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                crypto,
                &credential,
                &credential,
            )
            .unwrap();

        Self {
            kp: key_package,
            credential,
        }
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential.identity()
    }
}
