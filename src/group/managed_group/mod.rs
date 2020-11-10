use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::errors::ConfigError;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::tree::node::*;

pub struct ManagedGroup {
    pub group: MlsGroup,
    pub generation: u32,
    pub plaintext_queue: Vec<MLSPlaintext>,
    pub public_queue: ProposalQueue,
    pub own_queue: ProposalQueue,
    pub pending_kpbs: Vec<KeyPackageBundle>,
}

impl ManagedGroup {
    pub fn new(
        group_id: GroupId,
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, ConfigError> {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            ciphersuite_name,
            key_package_bundle,
            GroupConfig::default(),
        )?;

        Ok(ManagedGroup {
            group,
            generation: 0,
            plaintext_queue: vec![],
            public_queue: ProposalQueue::new(),
            own_queue: ProposalQueue::new(),
            pending_kpbs: vec![],
        })
    }
    pub fn new_from_welcome(
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle)?;
        Ok(ManagedGroup {
            group,
            generation: 0,
            plaintext_queue: vec![],
            public_queue: ProposalQueue::new(),
            own_queue: ProposalQueue::new(),
            pending_kpbs: vec![],
        })
    }
    pub fn new_with_members() {}
    pub fn add_member() {}
    pub fn remove_member() {}
    pub fn self_update() {}
    pub fn get_pending_proposals() {}

    pub fn send_application_message() {}

    pub fn get_members(&self) -> Vec<Credential> {
        let mut members = Vec::new();
        for i in 0..self.group.tree().leaf_count().as_usize() {
            let node = self.group.tree().nodes[i].clone();
            let credential = node.key_package.unwrap().credential().clone();
            members.push(credential);
        }
        members
    }
}

pub enum MLSMessage {
    Plaintext(MLSPlaintext),
    Ciphertext(MLSCiphertext),
}

pub enum GroupError {
    Codec(CodecError),
}

impl From<CodecError> for GroupError {
    fn from(err: CodecError) -> GroupError {
        GroupError::Codec(err)
    }
}
