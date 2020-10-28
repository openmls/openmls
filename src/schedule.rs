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

pub fn derive_secret(ciphersuite: &Ciphersuite, secret: &Secret, label: &str) -> Secret {
    hkdf_expand_label(ciphersuite, secret, label, &[], ciphersuite.hash_length())
}

pub fn mls_exporter(
    ciphersuite: &Ciphersuite,
    epoch_secrets: &EpochSecrets,
    label: &str,
    group_context: &GroupContext,
    key_length: usize,
) -> Secret {
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
    secret: &Secret,
    label: &str,
    context: &[u8],
    length: usize,
) -> Secret {
    let hkdf_label = HkdfLabel::new(context, label, length);
    let info = &hkdf_label.serialize();
    ciphersuite.hkdf_expand(secret, &info, length).unwrap()
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
    pub welcome_secret: Secret,
    pub sender_data_secret: Secret,
    pub encryption_secret: Secret,
    pub exporter_secret: Secret,
    pub confirmation_key: Secret,
    pub init_secret: Secret,
}

impl EpochSecrets {
    pub fn new() -> Self {
        let welcome_secret = Secret::new_empty_secret();
        let sender_data_secret = Secret::new_empty_secret();
        let encryption_secret = Secret::new_empty_secret();
        let exporter_secret = Secret::new_empty_secret();
        let confirmation_key = Secret::new_empty_secret();
        let init_secret = Secret::new_empty_secret();
        Self {
            welcome_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
    pub fn get_new_epoch_secrets(
        &mut self,
        ciphersuite: &Ciphersuite,
        commit_secret: Secret,
        psk: Option<Secret>,
        group_context: &GroupContext,
    ) -> Secret {
        let current_init_secret = self.init_secret.clone();
        let joiner_secret = &ciphersuite.hkdf_extract(&commit_secret, &current_init_secret);
        let welcome_secret = derive_secret(ciphersuite, &joiner_secret, "welcome");
        let pre_member_secret = derive_secret(ciphersuite, &joiner_secret, "member");
        let member_secret = ciphersuite.hkdf_extract(
            &psk.unwrap_or(Secret::new_empty_secret()),
            &pre_member_secret,
        );
        let pre_epoch_secret = derive_secret(ciphersuite, &member_secret, "epoch");
        let epoch_secret = ciphersuite.hkdf_extract(
            &Secret::new_from_bytes(group_context.serialize()),
            &pre_epoch_secret,
        );
        let epoch_secrets = Self::derive_epoch_secrets(ciphersuite, &epoch_secret, welcome_secret);
        self.welcome_secret = epoch_secrets.welcome_secret;
        self.sender_data_secret = epoch_secrets.sender_data_secret;
        self.encryption_secret = epoch_secrets.encryption_secret;
        self.exporter_secret = epoch_secrets.exporter_secret;
        self.confirmation_key = epoch_secrets.confirmation_key;
        self.init_secret = epoch_secrets.init_secret;
        epoch_secret
    }

    pub fn derive_epoch_secrets(
        ciphersuite: &Ciphersuite,
        epoch_secret: &Secret,
        welcome_secret: Secret,
    ) -> EpochSecrets {
        let sender_data_secret = derive_secret(ciphersuite, epoch_secret, "sender data");
        let encryption_secret = derive_secret(ciphersuite, epoch_secret, "encryption");
        let exporter_secret = derive_secret(ciphersuite, epoch_secret, "exporter");
        let confirmation_key = derive_secret(ciphersuite, epoch_secret, "confirm");
        let init_secret = derive_secret(ciphersuite, epoch_secret, "init");
        EpochSecrets {
            welcome_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            confirmation_key,
            init_secret,
        }
    }
}

impl Codec for EpochSecrets {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        &self.welcome_secret.encode(buffer)?;
        &self.sender_data_secret.encode(buffer)?;
        &self.encryption_secret.encode(buffer)?;
        &self.exporter_secret.encode(buffer)?;
        &self.confirmation_key.encode(buffer)?;
        &self.init_secret.encode(buffer)?;
        Ok(())
    }
}
