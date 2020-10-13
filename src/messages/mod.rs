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

use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::config::ProtocolVersion;
use crate::creds::*;
use crate::extensions::*;
use crate::group::*;
use crate::tree::{index::*, *};
use std::fmt;

pub(crate) mod proposals;
use proposals::*;

#[derive(Debug)]
pub enum MessageError {
    UnknownOperation,
}

pub struct MembershipChanges {
    pub updates: Vec<Credential>,
    pub removes: Vec<Credential>,
    pub adds: Vec<Credential>,
}

impl MembershipChanges {
    pub fn path_required(&self) -> bool {
        !self.updates.is_empty() || !self.removes.is_empty() || self.adds.is_empty()
    }
}

impl fmt::Debug for MembershipChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn list_members(f: &mut fmt::Formatter<'_>, members: &[Credential]) -> fmt::Result {
            for m in members {
                let Credential::Basic(bc) = m;
                write!(f, "{} ", String::from_utf8(bc.identity.clone()).unwrap())?;
            }
            Ok(())
        }
        write!(f, "Membership changes:")?;
        write!(f, "\n\tUpdates: ")?;
        list_members(f, &self.updates)?;
        write!(f, "\n\tRemoves: ")?;
        list_members(f, &self.removes)?;
        write!(f, "\n\tAdds: ")?;
        list_members(f, &self.adds)?;
        writeln!(f)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Commit {
    pub updates: Vec<ProposalID>,
    pub removes: Vec<ProposalID>,
    pub adds: Vec<ProposalID>,
    pub path: Option<UpdatePath>,
}

impl Codec for Commit {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.updates)?;
        encode_vec(VecSize::VecU32, buffer, &self.removes)?;
        encode_vec(VecSize::VecU32, buffer, &self.adds)?;
        self.path.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let updates = decode_vec(VecSize::VecU32, cursor)?;
    //     let removes = decode_vec(VecSize::VecU32, cursor)?;
    //     let adds = decode_vec(VecSize::VecU32, cursor)?;
    //     let path = Option::<UpdatePath>::decode(cursor)?;
    //     Ok(Commit {
    //         updates,
    //         removes,
    //         adds,
    //         path,
    //     })
    // }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConfirmationTag(pub Vec<u8>);

impl ConfirmationTag {
    pub fn new(
        ciphersuite: &Ciphersuite,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &[u8],
    ) -> Self {
        ConfirmationTag(ciphersuite.hkdf_extract(confirmation_key, confirmed_transcript_hash))
    }
    pub fn new_empty() -> Self {
        ConfirmationTag(vec![])
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Codec for ConfirmationTag {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let inner = decode_vec(VecSize::VecU8, cursor)?;
    //     Ok(ConfirmationTag(inner))
    // }
}

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CommitSecret(pub Vec<u8>);

impl CommitSecret {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Codec for CommitSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.0)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let inner = decode_vec(VecSize::VecU8, cursor)?;
    //     Ok(CommitSecret(inner))
    // }
}

pub struct GroupInfo {
    pub group_id: GroupId,
    pub epoch: GroupEpoch,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub interim_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Vec<u8>,
    pub signer_index: LeafIndex,
    pub signature: Signature,
}

impl GroupInfo {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut cursor = Cursor::new(bytes);
        let group_id = GroupId::decode(&mut cursor)?;
        let epoch = GroupEpoch::decode(&mut cursor)?;
        let tree_hash = decode_vec(VecSize::VecU8, &mut cursor)?;
        let confirmed_transcript_hash = decode_vec(VecSize::VecU8, &mut cursor)?;
        let interim_transcript_hash = decode_vec(VecSize::VecU8, &mut cursor)?;
        let extensions = decode_vec(VecSize::VecU16, &mut cursor)?;
        let confirmation_tag = decode_vec(VecSize::VecU8, &mut cursor)?;
        let signer_index = LeafIndex::from(u32::decode(&mut cursor)?);
        let signature = Signature::decode(&mut cursor)?;
        Ok(GroupInfo {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            interim_transcript_hash,
            extensions,
            confirmation_tag,
            signer_index,
            signature,
        })
    }
}

impl Codec for GroupInfo {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let group_id = GroupId::decode(cursor)?;
    //     let epoch = GroupEpoch::decode(cursor)?;
    //     let tree_hash = decode_vec(VecSize::VecU8, cursor)?;
    //     let confirmed_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
    //     let interim_transcript_hash = decode_vec(VecSize::VecU8, cursor)?;
    //     let extensions = decode_vec(VecSize::VecU16, cursor)?;
    //     let confirmation_tag = decode_vec(VecSize::VecU8, cursor)?;
    //     let signer_index = LeafIndex::from(u32::decode(cursor)?);
    //     let signature = Signature::decode(cursor)?;
    //     Ok(GroupInfo {
    //         group_id,
    //         epoch,
    //         tree_hash,
    //         confirmed_transcript_hash,
    //         interim_transcript_hash,
    //         extensions,
    //         confirmation_tag,
    //         signer_index,
    //         signature,
    //     })
    // }
}

impl Signable for GroupInfo {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut vec![];
        self.group_id.encode(buffer)?;
        self.epoch.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.tree_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmed_transcript_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.interim_transcript_hash)?;
        encode_vec(VecSize::VecU16, buffer, &self.extensions)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmation_tag)?;
        self.signer_index.encode(buffer)?;
        Ok(buffer.to_vec())
    }
}

pub struct PathSecret {
    pub path_secret: Vec<u8>,
}

impl Codec for PathSecret {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.path_secret)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let path_secret = decode_vec(VecSize::VecU8, cursor)?;
    //     Ok(PathSecret { path_secret })
    // }
}

pub struct GroupSecrets {
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
}

impl Codec for GroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.joiner_secret)?;
        self.path_secret.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let joiner_secret = decode_vec(VecSize::VecU8, cursor)?;
    //     let path_secret = Option::<PathSecret>::decode(cursor)?;
    //     Ok(GroupSecrets {
    //         joiner_secret,
    //         path_secret,
    //     })
    // }
}

#[derive(Clone)]
pub struct EncryptedGroupSecrets {
    pub key_package_hash: Vec<u8>,
    pub encrypted_group_secrets: HpkeCiphertext,
}

impl Codec for EncryptedGroupSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key_package_hash)?;
        self.encrypted_group_secrets.encode(buffer)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let key_package_hash = decode_vec(VecSize::VecU8, cursor)?;
    //     let encrypted_group_secrets = HpkeCiphertext::decode(cursor)?;
    //     Ok(EncryptedGroupSecrets {
    //         key_package_hash,
    //         encrypted_group_secrets,
    //     })
    // }
}

#[derive(Clone)]
pub struct Welcome {
    pub version: ProtocolVersion,
    pub cipher_suite: Ciphersuite,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>,
}

impl Codec for Welcome {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.secrets)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_group_info)?;
        Ok(())
    }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let version = ProtocolVersion::decode(cursor)?;
    //     let cipher_suite = Ciphersuite::decode(cursor)?;
    //     let secrets = decode_vec(VecSize::VecU32, cursor)?;
    //     let encrypted_group_info = decode_vec(VecSize::VecU32, cursor)?;
    //     Ok(Welcome {
    //         version,
    //         cipher_suite,
    //         secrets,
    //         encrypted_group_info,
    //     })
    // }
}

pub type WelcomeBundle = (Welcome, Extension);
