use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::ciphersuite::SignaturePublicKey;
use crate::credentials::Credential;

/// ExternalSender
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   SignaturePublicKey signature_key;
///   Credential credential;
/// } ExternalSender;
/// ```
#[derive(PartialEq, Eq, Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub(crate) struct ExternalSender {
    signature_key: SignaturePublicKey,
    credential: Credential,
}

/// ExternalSender (extension data)
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// ExternalSender external_senders<V>;
/// ```
// TODO(884): Remove `#[allow(unused)]` when #884 is closed.
#[allow(unused)]
pub(crate) type ExternalSenderExtension = Vec<ExternalSender>;

#[cfg(test)]
mod test {
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::SignatureScheme;
    use tls_codec::{Deserialize, Serialize};

    use crate::credentials::{CredentialBundle, CredentialType};

    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let tests = {
            let backend = OpenMlsRustCrypto::default();

            let mut external_sender_extensions = Vec::new();

            for _ in 0..8 {
                let credential_bundle = CredentialBundle::new(
                    b"Alice".to_vec(),
                    CredentialType::Basic,
                    SignatureScheme::ED25519,
                    &backend,
                )
                .expect("Creation of credential bundle failed.");

                let credential = credential_bundle.credential().clone();

                external_sender_extensions.push(ExternalSender {
                    signature_key: credential.signature_key().clone(),
                    credential: credential,
                });
            }

            external_sender_extensions
        };

        for expected in tests {
            let serialized = expected.tls_serialize_detached().unwrap();
            let serialized = &mut serialized.as_slice();

            let got = ExternalSender::tls_deserialize(serialized).unwrap();

            assert!(serialized.is_empty());
            assert_eq!(expected, got);
        }
    }
}
