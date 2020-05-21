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
use crate::creds::*;
use crate::crypto::dh::*;
use crate::crypto::hash::*;
use crate::crypto::hpke::*;
use crate::crypto::signatures::*;
use crate::utils::*;
use std::cmp::Ordering;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::*;

#[derive(Debug, PartialEq, Clone)]
pub struct KeyPackage {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: HPKEPublicKey,
    pub credential: Credential,
    pub extensions: Vec<Extension>,
    pub signature: Signature,
}

impl KeyPackage {
    pub fn new(ciphersuite: CipherSuite, init_key: &HPKEPublicKey, identity: &Identity) -> Self {
        let supported_version_extension =
            SupportedVersionsExtension::new(vec![CURRENT_PROTOCOL_VERSION]);
        let supported_ciphersuites_extension = SupportedCiphersuitesExtension::new(vec![
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ]);
        let lifetime_extension = LifetimeExtension::new(LifetimeExtension::LIFETIME_4_WEEKS);
        let extensions = vec![
            supported_version_extension.to_extension(),
            supported_ciphersuites_extension.to_extension(),
            lifetime_extension.to_extension(),
        ];
        KeyPackage::new_with_extensions(ciphersuite, init_key, identity, extensions)
    }
    pub fn new_with_extensions(
        ciphersuite: CipherSuite,
        hpke_init_key: &HPKEPublicKey,
        identity: &Identity,
        extensions: Vec<Extension>,
    ) -> Self {
        let credential = Credential::Basic(identity.into());
        let mut key_package = Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            cipher_suite: ciphersuite,
            hpke_init_key: hpke_init_key.to_owned(),
            credential,
            extensions,
            signature: Signature::new_empty(),
        };
        key_package.signature = identity.sign(&key_package.unsigned_payload().unwrap());
        key_package
    }
    pub fn self_verify(&self) -> bool {
        self.credential
            .verify(&self.unsigned_payload().unwrap(), &self.signature)
    }
    pub fn hash(&self) -> Vec<u8> {
        let bytes = self.encode_detached().unwrap();
        hash(HashAlgorithm::SHA256, &bytes)
    }
    pub fn has_extension(&self, extension_type: ExtensionType) -> bool {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                return true;
            }
        }
        false
    }
    pub fn get_extension(&self, extension_type: ExtensionType) -> Option<ExtensionPayload> {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                match extension_type {
                    ExtensionType::SupportedVersions => {
                        let supported_versions_extension =
                            SupportedVersionsExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::SupportedVersions(
                            supported_versions_extension,
                        ));
                    }
                    ExtensionType::SupportedCiphersuites => {
                        let supported_ciphersuites_extension =
                            SupportedCiphersuitesExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::SupportCiphersuites(
                            supported_ciphersuites_extension,
                        ));
                    }
                    ExtensionType::Lifetime => {
                        let lifetime_extension =
                            LifetimeExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::Lifetime(lifetime_extension));
                    }
                    ExtensionType::KeyID => {
                        let key_id_extension = KeyIDExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::KeyID(key_id_extension));
                    }
                    ExtensionType::ParentHash => {
                        let parent_hash_extension =
                            ParentHashExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::ParentHash(parent_hash_extension));
                    }
                    _ => return None,
                }
            }
        }
        None
    }
}

impl Signable for KeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut Vec::new();
        self.protocol_version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
        self.hpke_init_key.encode(buffer)?;
        self.credential.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.extensions)?;
        Ok(buffer.to_vec())
    }
}

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        // FIXME
        let protocol_version = ProtocolVersion::decode(cursor)?;
        let cipher_suite = CipherSuite::decode(cursor)?;
        let hpke_init_key = DHPublicKey::decode(cursor)?;
        let credential = Credential::decode(cursor)?;
        let extensions = decode_vec(VecSize::VecU16, cursor)?;
        let signature = Signature::decode(cursor)?;
        let kp = KeyPackage {
            protocol_version,
            cipher_suite,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        // TODO: check extensions

        let mut extensions = kp.extensions.clone();
        extensions.dedup();
        if kp.extensions.len() != extensions.len() {
            return Err(CodecError::DecodingError);
        }

        for e in extensions.iter() {
            match e.extension_type {
                ExtensionType::SupportedVersions => {
                    let supported_versions_extension =
                        SupportedVersionsExtension::new_from_bytes(&e.extension_data);
                    for v in supported_versions_extension.versions.iter() {
                        if *v > CURRENT_PROTOCOL_VERSION {
                            return Err(CodecError::DecodingError);
                        }
                    }
                }
                ExtensionType::SupportedCiphersuites => {
                    let supported_ciphersuites_extension =
                        SupportedCiphersuitesExtension::new_from_bytes(&e.extension_data);
                    if !supported_ciphersuites_extension
                        .contains(CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519)
                    {
                        return Err(CodecError::DecodingError);
                    }
                }
                ExtensionType::Lifetime => {
                    let lifetime_extension = LifetimeExtension::new_from_bytes(&e.extension_data);
                    if lifetime_extension.is_expired() {
                        return Err(CodecError::DecodingError);
                    }
                }
                ExtensionType::KeyID => {
                    let _key_id_extension = KeyIDExtension::new_from_bytes(&e.extension_data);
                }
                ExtensionType::ParentHash => {
                    let _parent_hash_extension =
                        ParentHashExtension::new_from_bytes(&e.extension_data);
                }
                ExtensionType::Invalid => {}
                ExtensionType::Default => {}
            }
        }

        for _ in 0..kp.extensions.len() {}

        if !kp.self_verify() {
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}

#[derive(Debug, Clone)]
pub struct KeyPackageBundle {
    pub key_package: KeyPackage,
    pub private_key: HPKEPrivateKey,
}

impl KeyPackageBundle {
    pub fn new(
        ciphersuite: CipherSuite,
        identity: &Identity,
        extensions_option: Option<Vec<Extension>>,
    ) -> Self {
        let keypair = HPKEKeyPair::new(ciphersuite.into()).unwrap();
        Self::new_with_keypair(ciphersuite, identity, extensions_option, &keypair)
    }
    pub fn new_with_keypair(
        ciphersuite: CipherSuite,
        identity: &Identity,
        extensions_option: Option<Vec<Extension>>,
        keypair: &HPKEKeyPair,
    ) -> Self {
        let private_key = keypair.private_key.clone();
        let supported_versions_extension =
            SupportedVersionsExtension::new(vec![ProtocolVersion::Mls10]).to_extension();
        let supported_ciphersuites_extension = SupportedCiphersuitesExtension::new(vec![
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ])
        .to_extension();
        let mut final_extensions = vec![
            supported_versions_extension,
            supported_ciphersuites_extension,
        ];
        if let Some(mut extensions) = extensions_option {
            final_extensions.append(&mut extensions);
        }
        let key_package = KeyPackage::new_with_extensions(
            ciphersuite,
            &keypair.public_key,
            identity,
            final_extensions,
        );
        KeyPackageBundle {
            key_package,
            private_key,
        }
    }
}

impl Codec for KeyPackageBundle {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key_package.encode(buffer)?;
        self.private_key.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package = KeyPackage::decode(cursor)?;
        let private_key = HPKEPrivateKey::decode(cursor)?;
        Ok(KeyPackageBundle {
            key_package,
            private_key,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolVersion {
    Mls10 = 0,
    Default = 255,
}

impl From<u8> for ProtocolVersion {
    fn from(a: u8) -> ProtocolVersion {
        unsafe { mem::transmute(a) }
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &ProtocolVersion) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &ProtocolVersion) -> Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl Codec for ProtocolVersion {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let version = u8::decode(cursor)?;
        Ok(version.into())
    }
}

pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    Invalid = 0,
    SupportedVersions = 1,
    SupportedCiphersuites = 2,
    Lifetime = 3,
    KeyID = 4,
    ParentHash = 5,
    Default = 65535,
}

impl From<u16> for ExtensionType {
    fn from(a: u16) -> ExtensionType {
        unsafe { mem::transmute(a) }
    }
}

impl Codec for ExtensionType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let extension = u16::decode(cursor)?;
        Ok(extension.into())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum ExtensionPayload {
    SupportedVersions(SupportedVersionsExtension),
    SupportCiphersuites(SupportedCiphersuitesExtension),
    Lifetime(LifetimeExtension),
    KeyID(KeyIDExtension),
    ParentHash(ParentHashExtension),
}

#[derive(PartialEq, Clone, Debug)]
pub struct SupportedVersionsExtension {
    versions: Vec<ProtocolVersion>,
}

impl SupportedVersionsExtension {
    pub fn new(versions: Vec<ProtocolVersion>) -> Self {
        SupportedVersionsExtension { versions }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let versions = decode_vec(VecSize::VecU8, cursor).unwrap();
        SupportedVersionsExtension { versions }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.versions).unwrap();
        let extension_type = ExtensionType::SupportedVersions;
        Extension {
            extension_type,
            extension_data,
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct SupportedCiphersuitesExtension {
    ciphersuites: Vec<CipherSuite>,
}

impl SupportedCiphersuitesExtension {
    pub fn new(ciphersuites: Vec<CipherSuite>) -> Self {
        Self { ciphersuites }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let ciphersuites = decode_vec(VecSize::VecU8, cursor).unwrap();
        Self { ciphersuites }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.ciphersuites).unwrap();
        let extension_type = ExtensionType::SupportedCiphersuites;
        Extension {
            extension_type,
            extension_data,
        }
    }
    pub fn contains(&self, ciphersuite: CipherSuite) -> bool {
        self.ciphersuites.contains(&ciphersuite)
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct LifetimeExtension {
    not_before: u64,
    not_after: u64,
}

impl LifetimeExtension {
    pub const LIFETIME_1_MINUTE: u64 = 60;
    pub const LIFETIME_1_HOUR: u64 = 60 * LifetimeExtension::LIFETIME_1_MINUTE;
    pub const LIFETIME_1_DAY: u64 = 24 * LifetimeExtension::LIFETIME_1_HOUR;
    pub const LIFETIME_1_WEEK: u64 = 7 * LifetimeExtension::LIFETIME_1_DAY;
    pub const LIFETIME_4_WEEKS: u64 = 4 * LifetimeExtension::LIFETIME_1_WEEK;
    pub const LIFETIME_MARGIN: u64 = LifetimeExtension::LIFETIME_1_HOUR;
    pub fn new(t: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_before = now - LifetimeExtension::LIFETIME_MARGIN;
        let not_after = now + t + LifetimeExtension::LIFETIME_MARGIN;
        Self {
            not_before,
            not_after,
        }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);
        let not_before = u64::decode(&mut cursor).unwrap();
        let not_after = u64::decode(&mut cursor).unwrap();
        Self {
            not_before,
            not_after,
        }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        self.not_before.encode(&mut extension_data).unwrap();
        self.not_after.encode(&mut extension_data).unwrap();
        let extension_type = ExtensionType::SupportedCiphersuites;
        Extension {
            extension_type,
            extension_data,
        }
    }
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.not_before < now && self.not_after > now
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct KeyIDExtension {
    key_id: Vec<u8>,
}

impl KeyIDExtension {
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let key_id = decode_vec(VecSize::VecU16, cursor).unwrap();
        Self { key_id }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU16, &mut extension_data, &self.key_id).unwrap();
        let extension_type = ExtensionType::KeyID;
        Extension {
            extension_type,
            extension_data,
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct ParentHashExtension {
    pub parent_hash: Vec<u8>,
}

impl ParentHashExtension {
    pub fn new(hash: &[u8]) -> Self {
        ParentHashExtension {
            parent_hash: hash.to_vec(),
        }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let parent_hash = decode_vec(VecSize::VecU8, cursor).unwrap();
        Self { parent_hash }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.parent_hash).unwrap();
        let extension_type = ExtensionType::ParentHash;
        Extension {
            extension_type,
            extension_data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl Extension {
    pub fn get_type(&self) -> ExtensionType {
        self.extension_type
    }
}

impl Codec for Extension {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.extension_type.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.extension_data)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::decode(cursor)?;
        let extension_data = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Extension {
            extension_type,
            extension_data,
        })
    }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct KeyPackageId {
    uuid: Uuid,
}

impl KeyPackageId {
    pub fn new() -> Self {
        let uuid = Uuid::from_slice(&randombytes(16)).unwrap();
        Self { uuid }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        let uuid = Uuid::from_slice(bytes).unwrap();
        Self { uuid }
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let bytes = self.uuid.as_bytes();
        bytes.to_vec()
    }
}

impl Codec for KeyPackageId {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.to_vec())?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let bytes = decode_vec(VecSize::VecU8, cursor)?;
        let id = KeyPackageId::from_slice(&bytes);
        Ok(id)
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
#[repr(u16)]
pub enum CipherSuite {
    MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 = 1,
    MLS10_128_HPKEP256_AES128GCM_SHA256_P256 = 2,
    MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 = 3,
    MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 = 4,
    MLS10_256_HPKEP521_AES256GCM_SHA512_P521 = 5,
    MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 = 6,
    Default = 65535,
}

impl From<u16> for CipherSuite {
    fn from(value: u16) -> Self {
        match value {
            1 => CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
            2 => CipherSuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256,
            3 => CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
            4 => CipherSuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448,
            5 => CipherSuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521,
            6 => CipherSuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448,
            _ => CipherSuite::Default,
        }
    }
}

impl Codec for CipherSuite {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(CipherSuite::from(u16::decode(cursor)?))
    }
}

#[test]
fn generate_key_package() {
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
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::Default;
    let mls10_e = mls10_version.encode_detached().unwrap();
    assert_eq!(mls10_e[0], mls10_version as u8);
    let default_e = default_version.encode_detached().unwrap();
    assert_eq!(default_e[0], default_version as u8);
    assert_eq!(mls10_e[0], 0);
    assert_eq!(default_e[0], 255);
}

#[test]
fn test_codec() {
    let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
    let identity = Identity::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        vec![1, 2, 3],
    );
    let kpb = KeyPackageBundle::new(ciphersuite, &identity, None);
    let enc = kpb.encode_detached().unwrap();
    let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    assert_eq!(kpb.key_package, kp);
}
