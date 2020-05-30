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

use crate::codec::*;
use crate::crypto::signatures::*;
use crate::kp::*;

#[derive(Clone)]
pub struct Identity {
    pub id: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub keypair: SignatureKeypair,
}

impl Identity {
    pub fn new(ciphersuite: CipherSuite, id: Vec<u8>) -> Self {
        let algorithm: SignatureAlgorithm = ciphersuite.into();
        let keypair = SignatureKeypair::new(algorithm).unwrap();
        Self {
            id,
            algorithm,
            keypair,
        }
    }
    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.keypair.sign(payload)
    }
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        self.keypair.verify(payload, signature)
    }
}

impl Codec for Identity {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.id)?;
        self.algorithm.encode(buffer)?;
        self.keypair.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let id = decode_vec(VecSize::VecU8, cursor)?;
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        let keypair = SignatureKeypair::decode(cursor)?;
        Ok(Identity {
            id,
            algorithm,
            keypair,
        })
    }
}

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum CredentialType {
    Basic = 0,
    X509 = 1,
    Default = 255,
}

impl From<u8> for CredentialType {
    fn from(value: u8) -> Self {
        match value {
            0 => CredentialType::Basic,
            1 => CredentialType::X509,
            _ => CredentialType::Default,
        }
    }
}

impl Codec for CredentialType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(CredentialType::from(u8::decode(cursor)?))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Credential {
    Basic(BasicCredential),
}

impl Credential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        match self {
            Credential::Basic(basic_credential) => {
                basic_credential.public_key.verify(payload, signature)
            }
        }
    }
}

impl Codec for Credential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Credential::Basic(basic_credential) => {
                CredentialType::Basic.encode(buffer)?;
                basic_credential.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let credential_type = CredentialType::from(u8::decode(cursor)?);
        match credential_type {
            CredentialType::Basic => Ok(Credential::Basic(BasicCredential::decode(cursor)?)),
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BasicCredential {
    pub identity: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub public_key: SignaturePublicKey,
}

impl BasicCredential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        self.public_key.verify(payload, signature)
    }
}

impl From<&Identity> for BasicCredential {
    fn from(identity: &Identity) -> Self {
        BasicCredential {
            identity: identity.id.clone(),
            algorithm: identity.algorithm,
            public_key: identity.keypair.get_public_key(),
        }
    }
}

impl Codec for BasicCredential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.identity)?;
        self.algorithm.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let identity = decode_vec(VecSize::VecU16, cursor)?;
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        Ok(BasicCredential {
            identity,
            algorithm,
            public_key,
        })
    }
}

#[test]
fn generate_key_package() {
    use crate::kp::*;
    let identity = Identity::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        vec![1, 2, 3],
    );
    let kp_bundle = KeyPackageBundle::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        &identity,
        None,
    );
    assert!(kp_bundle.key_package.self_verify());
}

#[test]
fn test_protocol_version() {
    use crate::kp::*;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::Default;
    let mls10_e = mls10_version.encode_detached().unwrap();
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version.encode_detached().unwrap();
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 0);
    assert_eq!(default_e[0], 255);
}
