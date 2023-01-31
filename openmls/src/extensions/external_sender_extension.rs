use serde::{Deserialize, Serialize};
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
#[derive(
    Clone, PartialEq, Eq, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ExternalSender {
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
pub type ExternalSendersExtension = Vec<ExternalSender>;

#[cfg(test)]
mod test {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::types::SignatureScheme;
    use tls_codec::{Deserialize, Serialize};

    use crate::credentials::CredentialType;

    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let tests = {
            let mut external_sender_extensions = Vec::new();

            for _ in 0..8 {
                let credential = Credential::new(b"Alice".to_vec(), CredentialType::Basic).unwrap();
                let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();

                external_sender_extensions.push(ExternalSender {
                    signature_key: signature_keys.to_public_vec().into(),
                    credential,
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
