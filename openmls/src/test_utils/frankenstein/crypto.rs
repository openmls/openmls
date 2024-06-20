use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::Ciphersuite};
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};

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
        .hkdf_extract(
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
