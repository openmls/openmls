// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use evercrypt::prelude::SignatureError;

use crate::ciphersuite::*;
use crate::codec::*;

use std::convert::TryFrom;

#[derive(Debug)]
pub enum CredentialError {
    UnsupportedCredentialType,
}

/// Enum for Credential Types. We only need this for encoding/decoding.
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum CredentialType {
    Reserved = 0,
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

impl Codec for CredentialType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        if let Ok(credential_type) = CredentialType::try_from(u16::decode(cursor)?) {
            Ok(credential_type)
        } else {
            Err(CodecError::DecodingError)
        }
    }
}

/// Struct containing an X509 certificate chain, as per Spec.
#[derive(Debug, PartialEq, Clone)]
pub struct Certificate {
    cert_data: Vec<u8>,
}

/// This enum contains the different available credentials.
#[derive(Debug, PartialEq, Clone)]
pub enum MLSCredentialType {
    Basic(BasicCredential),
    X509(Certificate),
}

/// Struct containing MLS credential data, where the data depends on the type.
#[derive(Debug, PartialEq, Clone)]
pub struct Credential {
    credential_type: CredentialType,
    credential: MLSCredentialType,
}

impl Credential {
    /// Verify a signature of a given payload against the public key contained
    /// in a credential.
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        match &self.credential {
            MLSCredentialType::Basic(basic_credential) => basic_credential.ciphersuite.verify(
                signature,
                &basic_credential.public_key,
                payload,
            ),
            // TODO: implement verification for X509 certificates. See issue #134.
            MLSCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
    /// Get the identity of a given credential.
    pub fn get_identity(&self) -> &Vec<u8> {
        match &self.credential {
            MLSCredentialType::Basic(basic_credential) => &basic_credential.identity,
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MLSCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }

    /// Get the ciphersuite associated with the credential.
    pub fn ciphersuite(&self) -> &Ciphersuite {
        match &self.credential {
            MLSCredentialType::Basic(basic_credential) => &basic_credential.ciphersuite,
            MLSCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
    }
}

impl From<MLSCredentialType> for Credential {
    fn from(mls_credential_type: MLSCredentialType) -> Self {
        Credential {
            credential_type: match mls_credential_type {
                MLSCredentialType::Basic(_) => CredentialType::Basic,
                MLSCredentialType::X509(_) => CredentialType::X509,
            },
            credential: mls_credential_type,
        }
    }
}

impl Codec for Credential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.credential {
            MLSCredentialType::Basic(basic_credential) => {
                CredentialType::Basic.encode(buffer)?;
                basic_credential.encode(buffer)?;
            }
            // TODO: implement encoding for X509 certificates
            MLSCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let credential_type = match CredentialType::try_from(u16::decode(cursor)?) {
            Ok(c) => c,
            Err(_) => return Err(CodecError::DecodingError),
        };
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MLSCredentialType::Basic(
                BasicCredential::decode(cursor)?,
            ))),
            _ => Err(CodecError::DecodingError),
        }
    }
}

// TODO: Drop ciphersuite
#[derive(Debug, Clone)]
pub struct BasicCredential {
    pub identity: Vec<u8>,
    pub ciphersuite: Ciphersuite,
    pub public_key: SignaturePublicKey,
}

impl BasicCredential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        self.ciphersuite
            .verify(signature, &self.public_key, payload)
    }
}

impl Codec for BasicCredential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.identity)?;
        self.ciphersuite.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let identity = decode_vec(VecSize::VecU16, cursor)?;
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        Ok(BasicCredential {
            identity,
            ciphersuite,
            public_key,
        })
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
    let mls10_e = mls10_version.encode_detached().unwrap();
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version.encode_detached().unwrap();
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 1);
    assert_eq!(default_e[0], 1);
}

/// This struct contains a credential and the corresponding private key.
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
        ciphersuite_name: CiphersuiteName,
    ) -> Result<Self, CredentialError> {
        let ciphersuite = Ciphersuite::new(ciphersuite_name);
        let (private_key, public_key) = ciphersuite.new_signature_keypair().into_tuple();
        let mls_credential = match credential_type {
            CredentialType::Basic => BasicCredential {
                identity,
                ciphersuite,
                public_key,
            },
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: MLSCredentialType::Basic(mls_credential),
        };
        Ok(CredentialBundle {
            credential,
            signature_private_key: private_key,
        })
    }

    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Sign a `msg` using the private key of the credential bundle.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Signature, SignatureError> {
        self.credential
            .ciphersuite()
            .sign(&self.signature_private_key, msg)
    }
}
