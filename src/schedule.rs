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
use crate::group::*;
use crate::messages::*;
use evercrypt::prelude::*;

pub fn derive_secret(ciphersuite: &Ciphersuite, secret: &[u8], label: &str) -> Vec<u8> {
    hkdf_expand_label(ciphersuite, secret, label, &[], ciphersuite.hash_length())
}

pub fn mls_exporter(
    ciphersuite: &Ciphersuite,
    epoch_secrets: &EpochSecrets,
    label: &str,
    group_context: &GroupContext,
    key_length: usize,
) -> Vec<u8> {
    let secret = &epoch_secrets.exporter_secret;
    let context = &group_context.serialize();
    let context_hash = &ciphersuite.hash(context);
    hkdf_expand_label(
        ciphersuite,
        &derive_secret(ciphersuite, secret, label),
        "exporter",
        context_hash,
        key_length,
    )
}

pub fn hkdf_expand_label(
    ciphersuite: &Ciphersuite,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let hkdf_label = HkdfLabel::new(context, label, length);
    let info = &hkdf_label.serialize();
    ciphersuite.hkdf_expand(&secret, &info, length).unwrap()
}

pub struct HkdfLabel {
    length: u16,
    label: String,
    context: Vec<u8>,
}

impl HkdfLabel {
    pub fn new(context: &[u8], label: &str, length: usize) -> Self {
        let full_label = "mls10 ".to_owned() + label;
        HkdfLabel {
            length: length as u16,
            label: full_label,
            context: context.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        (self.length as u16).encode(&mut buffer).unwrap();
        encode_vec(VecSize::VecU8, &mut buffer, self.label.as_bytes()).unwrap();
        encode_vec(VecSize::VecU32, &mut buffer, &self.context).unwrap();
        buffer
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct EpochSecrets {
    pub welcome_secret: Vec<u8>,
    pub sender_data_secret: Vec<u8>,
    pub handshake_secret: Vec<u8>,
    pub application_secret: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub init_secret: Vec<u8>,
}

impl EpochSecrets {
    pub fn new(ciphersuite: &Ciphersuite) -> Self {
        let welcome_secret = vec![];
        let sender_data_secret = vec![];
        let handshake_secret = vec![];
        let application_secret = vec![];
        let exporter_secret = vec![];
        let confirmation_key = vec![];
        let init_secret = get_random_vec(ciphersuite.hash_length());
        Self {
            welcome_secret,
            sender_data_secret,
            handshake_secret,
            application_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
    pub fn get_new_epoch_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        commit_secret: CommitSecret,
        psk: Option<&[u8]>,
        group_context: &GroupContext,
    ) -> Vec<u8> {
        let current_init_secret = self.init_secret.clone();
        let joiner_secret =
            &ciphersuite.hkdf_extract(commit_secret.as_slice(), &current_init_secret);
        let welcome_secret = derive_secret(ciphersuite, &joiner_secret, "welcome");
        let pre_member_secret = derive_secret(ciphersuite, &joiner_secret, "member");
        let member_secret = ciphersuite.hkdf_extract(&psk.unwrap_or(&[]), &pre_member_secret);
        let pre_epoch_secret = derive_secret(ciphersuite, &member_secret, "epoch");
        let epoch_secret = ciphersuite.hkdf_extract(&group_context.serialize(), &pre_epoch_secret);
        let epoch_secrets = Self::derive_epoch_secrets(ciphersuite, &epoch_secret, welcome_secret);
        self.welcome_secret = epoch_secrets.welcome_secret;
        self.sender_data_secret = epoch_secrets.sender_data_secret;
        self.handshake_secret = epoch_secrets.handshake_secret;
        self.application_secret = epoch_secrets.application_secret;
        self.exporter_secret = epoch_secrets.exporter_secret;
        self.confirmation_key = epoch_secrets.confirmation_key;
        self.init_secret = epoch_secrets.init_secret;
        epoch_secret
    }

    pub fn derive_epoch_secrets(
        ciphersuite: &Ciphersuite,
        epoch_secret: &[u8],
        welcome_secret: Vec<u8>,
    ) -> EpochSecrets {
        let sender_data_secret = derive_secret(ciphersuite, epoch_secret, "sender data");
        let handshake_secret = derive_secret(ciphersuite, epoch_secret, "handshake");
        let application_secret = derive_secret(ciphersuite, epoch_secret, "app");
        let exporter_secret = derive_secret(ciphersuite, epoch_secret, "exporter");
        let confirmation_key = derive_secret(ciphersuite, epoch_secret, "confirm");
        let init_secret = derive_secret(ciphersuite, epoch_secret, "init");
        EpochSecrets {
            welcome_secret,
            sender_data_secret,
            handshake_secret,
            application_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
}

impl Codec for EpochSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.welcome_secret)?;
        encode_vec(VecSize::VecU8, buffer, &self.sender_data_secret)?;
        encode_vec(VecSize::VecU8, buffer, &self.handshake_secret)?;
        encode_vec(VecSize::VecU8, buffer, &self.application_secret)?;
        encode_vec(VecSize::VecU8, buffer, &self.exporter_secret)?;
        encode_vec(VecSize::VecU8, buffer, &self.confirmation_key)?;
        encode_vec(VecSize::VecU8, buffer, &self.init_secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let welcome_secret = decode_vec(VecSize::VecU8, cursor)?;
        let sender_data_secret = decode_vec(VecSize::VecU8, cursor)?;
        let handshake_secret = decode_vec(VecSize::VecU8, cursor)?;
        let application_secret = decode_vec(VecSize::VecU8, cursor)?;
        let exporter_secret = decode_vec(VecSize::VecU8, cursor)?;
        let confirmation_key = decode_vec(VecSize::VecU8, cursor)?;
        let init_secret = decode_vec(VecSize::VecU8, cursor)?;
        Ok(EpochSecrets {
            welcome_secret,
            sender_data_secret,
            handshake_secret,
            application_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        })
    }
}
