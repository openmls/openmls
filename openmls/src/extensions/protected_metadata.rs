use std::time::{SystemTime, UNIX_EPOCH};

use openmls_traits::signatures::Signer;
use tls_codec::{Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::{
    ciphersuite::{
        signable::{Signable, SignatureError, SignedStruct, Verifiable, VerifiedStruct},
        signature::Signature,
    },
    credentials::Credential,
};

/// # Protected Metadata
///
/// ```c
/// struct {
///   opaque signer_application_id<V>;
///   Credential signer_credential;
///   SignaturePublicKey signature_key;
///   uint64 signing_time;
///   opaque metadata<V>;
///   /* SignWithLabel(., "ProtectedMetadataTBS",ProtectedMetadata) */
///   opaque signature<V>;
/// } ProtectedMetadata;
/// ```
///
/// This extension must be verified by the application every time it is set or
/// changed.
/// The application **MUST** verify that
/// * the signature is valid (using `verify_no_out` on this.)
/// * the credential has been valid at `signing_time`
/// * the `signer_application_id` is equal to the `creator_application_id`.
///
/// FIXME: This should NOT be deserializable. But we need to change more code for
///        that to be possible.
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ProtectedMetadata {
    payload: ProtectedMetadataTbs,
    signature: Signature,
}

impl ProtectedMetadata {
    /// Create a new protected metadata extension and sign it.
    pub fn new(
        signer: &impl Signer,
        signer_application_id: Vec<u8>,
        signer_credential: Credential,
        signature_key: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<Self, SignatureError> {
        let tbs = ProtectedMetadataTbs::new(
            signer_application_id,
            signer_credential,
            signature_key,
            metadata,
        );
        tbs.sign(signer)
    }

    /// Get the signer application ID as slice.
    pub fn signer_application_id(&self) -> &[u8] {
        self.payload.signer_application_id.as_ref()
    }

    /// Get the signer [`Credential`].
    pub fn signer_credential(&self) -> &Credential {
        &self.payload.signer_credential
    }

    /// Get the signature key as slize.
    pub fn signature_key(&self) -> &[u8] {
        self.payload.signature_key.as_ref()
    }

    /// Get the signing time as UNIX timestamp.
    pub fn signing_time(&self) -> u64 {
        self.payload.signing_time
    }

    /// Get the serialized metadata as slice.
    ///
    /// This is opaque to OpenMLS. The caller must handle it appropriately.
    pub fn metadata(&self) -> &[u8] {
        self.payload.metadata.as_ref()
    }
}

impl SignedStruct<ProtectedMetadataTbs> for ProtectedMetadata {
    fn from_payload(payload: ProtectedMetadataTbs, signature: Signature) -> Self {
        ProtectedMetadata { payload, signature }
    }
}

/// # Protected Metadata
///
/// ```c
/// /* SignWithLabel(., "ProtectedMetadataTBS",ProtectedMetadata) */
/// struct {
///   opaque signer_application_id<V>;
///   Credential signer_credential;
///   SignaturePublicKey signature_key;
///   uint64 signing_time;
///   opaque metadata<V>;
/// } ProtectedMetadataTBS;
/// ```
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ProtectedMetadataTbs {
    signer_application_id: Vec<u8>,
    signer_credential: Credential,
    signature_key: Vec<u8>,
    signing_time: u64,
    metadata: Vec<u8>,
}

impl ProtectedMetadataTbs {
    /// Create a protected metadata extension tbs.
    fn new(
        signer_application_id: Vec<u8>,
        signer_credential: Credential,
        signature_key: Vec<u8>,
        metadata: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            signer_application_id,
            signer_credential,
            signature_key,
            signing_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX EPOCH!")
                .as_secs(),
            metadata: metadata.into(),
        }
    }
}

const SIGNATURE_LABEL: &str = "ProtectedMetadataTbs";

impl Signable for ProtectedMetadataTbs {
    type SignedOutput = ProtectedMetadata;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_LABEL
    }
}

/// XXX: This really should not be implemented on [`ProtectedMetadata`] but on
/// the verifiable version.
mod verifiable {
    use openmls_traits::crypto::OpenMlsCrypto;

    use crate::prelude::OpenMlsSignaturePublicKey;

    use super::*;

    impl Verifiable for ProtectedMetadata {
        type VerifiedStruct = ProtectedMetadata;

        fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
            self.payload.tls_serialize_detached()
        }

        fn signature(&self) -> &Signature {
            &self.signature
        }

        fn label(&self) -> &str {
            SIGNATURE_LABEL
        }

        fn verify(
            self,
            crypto: &impl OpenMlsCrypto,
            pk: &OpenMlsSignaturePublicKey,
        ) -> Result<Self::VerifiedStruct, SignatureError> {
            self.verify_no_out(crypto, pk)?;
            Ok(self)
        }
    }

    impl VerifiedStruct for ProtectedMetadata {}

    mod private_mod {
        #[derive(Default)]
        pub struct Seal;
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        credentials::test_utils::new_credential, extensions::protected_metadata::ProtectedMetadata,
        prelude_test::OpenMlsSignaturePublicKey, test_utils::*,
    };

    use super::*;

    #[apply(ciphersuites_and_providers)]
    fn serialize_extension(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
        let creator_application_id = b"MetadataTestAppId".to_vec();

        // Create metadata
        let metadata = vec![1, 2, 3];

        // Setup crypto
        let (credential_with_key, signer) = new_credential(
            provider,
            b"Kreator",
            crate::credentials::CredentialType::Basic,
            ciphersuite.signature_algorithm(),
        );
        let signature_key =
            OpenMlsSignaturePublicKey::new(signer.public().into(), ciphersuite.into()).unwrap();

        let signer_application_id = creator_application_id.clone();
        let extension = ProtectedMetadata::new(
            &signer,
            signer_application_id,
            credential_with_key.credential.clone(),
            signature_key.as_slice().to_vec(),
            metadata.clone(),
        )
        .unwrap();

        // serialize and deserialize + verify
        let serialized = extension.tls_serialize_detached().unwrap();
        let protected_metadata = ProtectedMetadata::tls_deserialize_exact(serialized).unwrap();
        protected_metadata
            .verify_no_out(provider.crypto(), &signature_key)
            .unwrap();
        assert_eq!(protected_metadata, extension);

        // XXX: Application has to
        // * the credential has been valid at `signing_time`

        let xmtp_metadata = protected_metadata.metadata();
        assert_eq!(xmtp_metadata, metadata);

        // But really, the extension must never be modified.
    }
}
