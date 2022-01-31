//! # Credentials
//!
//! Credentials are used to to authenticate messages and members of a group are represented
//! by a Credential. Clients create a [`CredentialBundle`] which contains the private key material
//! and expose a [`Credential`] in the key packages they generate.
//!
//! The MLS protocol spec allows credentials to change over time. Concretely, members can issue an Update proposal
//! or a Full Commit to update their credential. The new credential still needs to be signed by the old credential.
//!
//! When receiving a credential update from another member, applications must ensure the new credential is valid
//! and need to query the Authentication Service for that matter.
//!
//! Credentials are specific to a signature scheme, which is part of the ciphersuite of a group. Clients can have several
//! credentials with different signature schemes.

mod codec;
mod errors;
pub use errors::*;
#[cfg(test)]
mod tests;

use openmls_traits::{
    types::{CryptoError, SignatureScheme},
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
#[cfg(test)]
use tls_codec::Serialize as TlsSerializeTrait;
use tls_codec::{TlsByteVecU16, TlsDeserialize, TlsSerialize, TlsSize};

use crate::ciphersuite::*;

/// Enum for Credential Types. We only need this for encoding/decoding.
#[derive(
    Copy, Clone, Debug, PartialEq, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u16)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic = 1,
    /// An X.509 [`Certificate`]
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
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`]
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
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential
                .public_key
                .verify(backend, signature, payload)
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

/// A `BasicCredential as defined in the MLS protocol spec:
///
/// ```text
/// struct {
///     opaque identity<0..2^16-1>;
///     SignatureScheme signature_scheme;
///     opaque signature_key<0..2^16-1>;
/// } BasicCredential;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    identity: TlsByteVecU16,
    signature_scheme: SignatureScheme,
    public_key: SignaturePublicKey,
}

impl BasicCredential {
    /// Verifies a signature issued by a [`BasicCredential`]. Returns a [`CredentialError`]
    /// if the verification fails.
    pub fn verify(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        payload: &[u8],
        signature: &Signature,
    ) -> Result<(), CredentialError> {
        self.public_key
            .verify(backend, signature, payload)
            .map_err(|_| CredentialError::InvalidSignature)
    }
}

impl PartialEq for BasicCredential {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity && self.public_key == other.public_key
    }
}

/// This struct contains a credential and the corresponding private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct CredentialBundle {
    credential: Credential,
    signature_private_key: SignaturePrivateKey,
}

impl CredentialBundle {
    /// Create a new `CredentialBundle` of the given credential type for the
    /// given identity and ciphersuite. The corresponding `SignatureKeyPair` is
    /// freshly generated.
    pub fn new(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Self, CredentialError> {
        let (private_key, public_key) =
            SignatureKeypair::new(signature_scheme, backend)?.into_tuple();
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
        Ok(CredentialBundle {
            credential,
            signature_private_key: private_key,
        })
    }

    /// Creates a new [CredentialBundle] from an identity and a [SignatureKeypair].
    /// Note that only [BasicCredential] is currently supported.
    pub fn from_parts(identity: Vec<u8>, keypair: SignatureKeypair) -> Self {
        let (signature_private_key, public_key) = keypair.into_tuple();
        let basic_credential = BasicCredential {
            identity: identity.into(),
            signature_scheme: public_key.signature_scheme(),
            public_key,
        };
        let credential = Credential {
            credential_type: CredentialType::Basic,
            credential: MlsCredentialType::Basic(basic_credential),
        };
        Self {
            credential,
            signature_private_key,
        }
    }

    /// Returns a reference to the [`Credential`].
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Sign a `msg` using the private key of the credential bundle.
    pub(crate) fn sign(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        msg: &[u8],
    ) -> Result<Signature, CryptoError> {
        self.signature_private_key.sign(backend, msg)
    }
}
