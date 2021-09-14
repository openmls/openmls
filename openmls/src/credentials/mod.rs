mod codec;
mod errors;
pub use codec::*;
pub use errors::*;

use evercrypt::prelude::SignatureError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{Size, TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

use crate::ciphersuite::*;

/// Enum for Credential Types. We only need this for encoding/decoding.
#[derive(
    Copy, Clone, Debug, PartialEq, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u16)]
pub enum CredentialType {
    Basic = 1,
    X509 = 2,
}

impl TryFrom<u16> for CredentialType {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CredentialType::Basic),
            2 => Ok(CredentialType::X509),
            _ => Err("Undefined CredentialType"),
        }
    }
}

/// Struct containing an X509 certificate chain, as per Spec.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    cert_data: Vec<u8>,
}

/// This enum contains the different available credentials.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    Basic(BasicCredential),
    X509(Certificate),
}

/// Struct containing MLS credential data, where the data depends on the type.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Credential {
    credential_type: CredentialType,
    credential: MlsCredentialType,
}

impl Credential {
    /// Verify a signature of a given payload against the public key contained
    /// in a credential.
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> Result<(), CredentialError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential
                .public_key
                .verify(signature, payload)
                .map_err(|_| CredentialError::InvalidSignature),
            // TODO: implement verification for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }

    /// Get the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
    /// Get the signature scheme used by the credential.
    pub fn signature_scheme(&self) -> SignatureScheme {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.signature_scheme,
            // TODO: implement getter for signature scheme for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
    /// Get the public key contained in the credential.
    pub fn signature_key(&self) -> &SignaturePublicKey {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => &basic_credential.public_key,
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
}

impl From<MlsCredentialType> for Credential {
    fn from(mls_credential_type: MlsCredentialType) -> Self {
        Credential {
            credential_type: match mls_credential_type {
                MlsCredentialType::Basic(_) => CredentialType::Basic,
                MlsCredentialType::X509(_) => CredentialType::X509,
            },
            credential: mls_credential_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    identity: TlsByteVecU16,
    signature_scheme: SignatureScheme,
    public_key: SignaturePublicKey,
}

impl BasicCredential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> Result<(), CredentialError> {
        self.public_key
            .verify(signature, payload)
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

impl PartialEq for BasicCredential {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.public_key == other.public_key
    }
}

#[test]
fn test_protocol_version() {
    use crate::config::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();
    let mls10_e = mls10_version.tls_serialize_detached().unwrap();
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version.tls_serialize_detached().unwrap();
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 1);
    assert_eq!(default_e[0], 1);
}

/// This struct contains a credential and the corresponding private key.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CredentialBundleOld {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl CredentialBundleOld {
    /// Create a new `CredentialBundle` of the given credential type for the
    /// given identity and ciphersuite. The corresponding `SignatureKeyPair` is
    /// freshly generated.
    pub fn new(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
    ) -> Result<Self, CredentialError> {
        let (private_key, public_key) = signature_scheme.new_keypair()?.into_tuple();
        let mls_credential = match credential_type {
            CredentialType::Basic => BasicCredential {
                identity: identity.into(),
                signature_scheme,
                public_key,
            },
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: MlsCredentialType::Basic(mls_credential),
        };
        Ok(CredentialBundleOld {
            credential,
            signature_private_key: private_key,
        })
    }

    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Sign a `msg` using the private key of the credential bundle.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        self.signature_private_key.sign(msg)
    }
}

/// This struct contains a credential and the corresponding private key.
pub trait CredentialBundle: core::fmt::Debug {
    /// Create a new `CredentialBundle` of the given credential type for the
    /// given identity and ciphersuite. The corresponding `SignatureKeyPair` is
    /// freshly generated.
    fn new(identity: Vec<u8>, signature_scheme: SignatureScheme) -> Result<Self, CredentialError>
    where
        Self: Sized;
    /// Return the credential of the credential bundle.
    fn credential(&self) -> &Credential;
    /// Sign a `msg` using the private key of the credential bundle.
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError>;
}

#[derive(Debug)]
pub struct BasicCredentialBundle {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl BasicCredentialBundle {
    pub fn new_from_values(
        identity: Vec<u8>,
        signature_scheme: SignatureScheme,
        private_key: SignaturePrivateKey,
        public_key: SignaturePublicKey,
    ) -> Self {
        let basic_credential = BasicCredential {
            identity: identity.into(),
            signature_scheme,
            public_key,
        };
        Self {
            credential: Credential {
                credential_type: CredentialType::Basic,
                credential: MlsCredentialType::Basic(basic_credential),
            },
            signature_private_key: private_key,
        }
    }
}

impl CredentialBundle for BasicCredentialBundle {
    fn new(identity: Vec<u8>, signature_scheme: SignatureScheme) -> Result<Self, CredentialError> {
        let (private_key, public_key) = signature_scheme.new_keypair()?.into_tuple();
        Ok(Self::new_from_values(
            identity,
            signature_scheme,
            private_key,
            public_key,
        ))
    }

    fn credential(&self) -> &Credential {
        &self.credential
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        self.signature_private_key.sign(msg)
    }
}
