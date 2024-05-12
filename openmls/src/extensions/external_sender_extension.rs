use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{ciphersuite::SignaturePublicKey, credentials::Credential};

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
    Clone,
    PartialEq,
    Eq,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ExternalSender {
    signature_key: SignaturePublicKey,
    credential: Credential,
}

impl ExternalSender {
    /// Creates a new `ExternalSender` instance.
    pub fn new(signature_key: SignaturePublicKey, credential: Credential) -> Self {
        Self {
            signature_key,
            credential,
        }
    }

    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }

    pub(crate) fn signature_key(&self) -> &SignaturePublicKey {
        &self.signature_key
    }
}

/// ExternalSender (extension data)
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// ExternalSender external_senders<V>;
/// ```
pub type ExternalSendersExtension = Vec<ExternalSender>;
/// Identifies an external sender in the `ExternalSendersExtension`.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct SenderExtensionIndex(u32);

impl SenderExtensionIndex {
    /// Creates a new `SenderExtensionIndex` instance.
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the internal index as usize
    pub(crate) fn index(&self) -> usize {
        self.0 as usize
    }
}

#[cfg(test)]
mod test {
    use openmls_basic_credential::SignatureKeyPair;
    use tls_codec::{Deserialize, Serialize};

    use super::*;
    use crate::credentials::BasicCredential;

    #[openmls_test::openmls_test]
    fn test_serialize_deserialize() {
        let tests = {
            let mut external_sender_extensions = Vec::new();

            for _ in 0..8 {
                let credential = BasicCredential::new(b"Alice".to_vec());
                let signature_keys =
                    SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

                external_sender_extensions.push(ExternalSender {
                    signature_key: signature_keys.to_public_vec().into(),
                    credential: credential.into(),
                });
            }

            external_sender_extensions
        };

        for expected in tests {
            let serialized = expected.tls_serialize_detached().unwrap();
            let got = ExternalSender::tls_deserialize_exact(serialized).unwrap();
            assert_eq!(expected, got);
        }
    }
}
