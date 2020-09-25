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

use crate::ciphersuite::*;
use crate::codec::*;
use crate::extensible_credential::ExtensibleCredential;

#[derive(Clone)]
pub struct Identity {
    pub id: Vec<u8>,
    pub ciphersuite: Ciphersuite,
    keypair: SignatureKeypair,
}

impl Identity {
    pub fn new(ciphersuite: Ciphersuite, id: Vec<u8>) -> Self {
        let keypair = ciphersuite.new_signature_keypair();
        Self {
            id,
            ciphersuite,
            keypair,
        }
    }
    pub fn new_with_keypair(
        ciphersuite: Ciphersuite,
        id: Vec<u8>,
        keypair: SignatureKeypair,
    ) -> Self {
        Self {
            id,
            ciphersuite,
            keypair,
        }
    }
    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.ciphersuite
            .sign(self.keypair.get_private_key(), payload)
            .unwrap()
    }
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        self.ciphersuite
            .verify(signature, self.keypair.get_public_key(), payload)
    }
    pub fn get_signature_key_pair(&self) -> &SignatureKeypair {
        &self.keypair
    }
}

impl Codec for Identity {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.id)?;
        self.ciphersuite.encode(buffer)?;
        self.keypair.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let id = decode_vec(VecSize::VecU8, cursor)?;
    //     let ciphersuite = Ciphersuite::decode(cursor)?;
    //     let keypair = SignatureKeypair::decode(cursor)?;
    //     Ok(Identity {
    //         id,
    //         ciphersuite,
    //         keypair,
    //     })
    // }
}

#[derive(Copy, Clone)]
#[repr(u16)]
pub enum CredentialType {
    Reserved = 0x0,
    Basic = 1,
    X509 = 2,
    Extensible = 0xff00,
    Default = 65535,
}

impl From<u16> for CredentialType {
    fn from(value: u16) -> Self {
        match value {
            0 => CredentialType::Reserved,
            1 => CredentialType::Basic,
            2 => CredentialType::X509,
            0xff00 => CredentialType::Extensible,
            _ => CredentialType::Default,
        }
    }
}

impl Codec for CredentialType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     Ok(CredentialType::from(u8::decode(cursor)?))
    // }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Credential {
    Basic(BasicCredential),
    Extensible(ExtensibleCredential),
}

/// TODO: Shouldn't this be a trait that we implement for the individual
/// credentials?
impl Credential {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        match self {
            Credential::Basic(basic_credential) => basic_credential.ciphersuite.verify(
                signature,
                &basic_credential.public_key,
                payload,
            ),
            Credential::Extensible(extensible_credential) => extensible_credential
                .ciphersuite
                .verify(signature, &extensible_credential.public_key, payload),
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
            Credential::Extensible(extensible_credential) => {
                CredentialType::Extensible.encode(buffer)?;
                extensible_credential.encode(buffer)?;
            }
        }
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let credential_type = CredentialType::from(u8::decode(cursor)?);
    //     match credential_type {
    //         CredentialType::Basic => Ok(Credential::Basic(BasicCredential::decode(cursor)?)),
    //         _ => Err(CodecError::DecodingError),
    //     }
    // }
}

// TODO: Drop ciphersuite
#[derive(Debug, Clone, PartialEq)]
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

impl From<&Identity> for BasicCredential {
    fn from(identity: &Identity) -> Self {
        BasicCredential {
            identity: identity.id.clone(),
            ciphersuite: identity.ciphersuite,
            public_key: identity.keypair.get_public_key().clone(),
        }
    }
}

impl Codec for BasicCredential {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.identity)?;
        self.ciphersuite.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let identity = decode_vec(VecSize::VecU16, cursor)?;
    //     let ciphersuite = Ciphersuite::decode(cursor)?;
    //     let public_key = SignaturePublicKey::decode(cursor)?;
    //     Ok(BasicCredential {
    //         identity,
    //         ciphersuite,
    //         public_key,
    //     })
    // }
}

#[test]
fn test_protocol_version() {
    use crate::extensions::*;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::Default;
    let mls10_e = mls10_version.encode_detached().unwrap();
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version.encode_detached().unwrap();
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 0);
    assert_eq!(default_e[0], 255);
}
