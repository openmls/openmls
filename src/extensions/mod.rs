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

mod capabilities_extension;
mod key_package_id_extension;
mod life_time_extension;
mod parent_hash_extension;
mod ratchet_tree_extension;

pub(crate) use capabilities_extension::CapabilitiesExtension;
pub(crate) use key_package_id_extension::KeyIDExtension;
pub(crate) use life_time_extension::LifetimeExtension;
pub(crate) use parent_hash_extension::ParentHashExtension;
pub(crate) use ratchet_tree_extension::RatchetTreeExtension;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExtensionError {
    UnknownExtension,
}

/// # Extension types
///
/// [IANA registrations](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-mls-extension-types)
///
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ExtensionType {
    Reserved = 0,
    Capabilities = 1,
    Lifetime = 2,
    KeyID = 3,
    ParentHash = 4,
    RatchetTree = 5,
}

/// The default extension type is invalid.
/// This has to be set explicitly.
impl Default for ExtensionType {
    fn default() -> Self {
        ExtensionType::Reserved
    }
}

impl ExtensionType {
    /// Get the `ExtensionType` from a u16.
    /// Returns an error if the extension type is not known.
    pub(crate) fn from(a: u16) -> Result<ExtensionType, ExtensionError> {
        match a {
            0 => Ok(ExtensionType::Reserved),
            1 => Ok(ExtensionType::Capabilities),
            2 => Ok(ExtensionType::Lifetime),
            3 => Ok(ExtensionType::KeyID),
            4 => Ok(ExtensionType::ParentHash),
            5 => Ok(ExtensionType::RatchetTree),
            _ => Err(ExtensionError::UnknownExtension),
        }
    }
}

impl Codec for ExtensionType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(buffer)?;
        Ok(())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub(crate) enum ExtensionPayload {
    Capabilities(CapabilitiesExtension),
    Lifetime(LifetimeExtension),
    KeyID(KeyIDExtension),
    ParentHash(ParentHashExtension),
    RatchetTree(RatchetTreeExtension),
}


/// # Extension
/// 
/// An extension has an `ExtensionType` and an opaque payload (byte vector).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Vec<u8>,
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

    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let extension_type = ExtensionType::decode(cursor)?;
    //     let extension_data = decode_vec(VecSize::VecU16, cursor)?;
    //     Ok(Extension {
    //         extension_type,
    //         extension_data,
    //     })
    // }
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

#[test]
fn test_extension_codec() {
    use crate::config::ProtocolVersion;
    use crate::key_packages::*;

    let capabilities_extension = CapabilitiesExtension::new(
        ProtocolVersion::supported(),
        CIPHERSUITES.to_vec(),
        SUPPORTED_EXTENSIONS.to_vec(),
    );
    let extension = capabilities_extension.to_extension();
    let _bytes = extension.encode_detached().unwrap();
    // let _dec = Extension::decode(&mut Cursor::new(&bytes));
}
