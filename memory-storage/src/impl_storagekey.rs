use openmls_spec_types::{
    key_package::KeyPackageRef,
    keys::{EncryptionKey, InitKey},
    proposals::ProposalRef,
    GroupId,
};

use openmls_traits::storage::{EpochKeyPairId, Key, PskBundleId};

use std::io::Write;

use crate::StorageKey;

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum Domain {
    EpochKeyPair = 1,
    InitKey = 2,
    EncryptionKey = 3,
    KeyPackage = 4,
    PskBundle = 5,
    Proposal = 6,
    QueuedProposals = 7,
    Group = 0xff01, // should be phased out soon, so give it a bad value
}

impl Domain {
    fn prefix(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

pub struct QueuedProposals;

impl StorageKey for EpochKeyPairId {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::EpochKeyPair, &self.0)
    }

    fn into_key(self) -> Key {
        Key::EpochKeyPair(self)
    }
}

impl StorageKey for QueuedProposals {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::QueuedProposals, b"")
    }

    fn into_key(self) -> Key {
        Key::QueuedProposals
    }
}

// TODO: add macros for impl these

impl StorageKey for InitKey {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::InitKey, &self.key)
    }

    fn into_key(self) -> Key {
        Key::InitKey(self)
    }
}
impl StorageKey for EncryptionKey {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::EncryptionKey, &self.key)
    }

    fn into_key(self) -> Key {
        Key::EncryptionKey(self)
    }
}

impl StorageKey for KeyPackageRef {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::KeyPackage, &self.0.value)
    }

    fn into_key(self) -> Key {
        Key::KeyPackage(self)
    }
}

impl StorageKey for PskBundleId {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::PskBundle, &self.0)
    }

    fn into_key(self) -> Key {
        Key::PskBundle(self)
    }
}

impl StorageKey for ProposalRef {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::Proposal, &self.0.value)
    }

    fn into_key(self) -> Key {
        Key::Proposal(self)
    }
}

impl StorageKey for GroupId {
    fn key_bytes(&self) -> Vec<u8> {
        build_key(Domain::Group, &self.value)
    }

    fn into_key(self) -> Key {
        Key::Group(self)
    }
}

fn build_key(domain: Domain, bytes: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + bytes.len());
    key.write_all(&domain.prefix()).unwrap();
    key.write_all(bytes).unwrap();
    key
}
