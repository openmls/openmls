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
use crate::creds::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::tree::{index::*, node::*};

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
        ciphersuite: Ciphersuite,
        key_package_bundle: KeyPackageBundle,
    ) -> Self {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            ciphersuite,
            KeyPackageBundle {
                private_key: key_package_bundle.get_private_key().clone(),
                key_package: key_package_bundle.get_key_package().clone(),
            },
        );

        ManagedGroup {
            group,
            generation: 0,
            plaintext_queue: vec![],
            public_queue: ProposalQueue::new(),
            own_queue: ProposalQueue::new(),
            pending_kpbs: vec![],
        }
    }
    pub fn new_from_welcome(
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        let group = MlsGroup::new_from_welcome(
            welcome,
            ratchet_tree,
            KeyPackageBundle {
                private_key: key_package_bundle.get_private_key().clone(),
                key_package: key_package_bundle.get_key_package().clone(),
            },
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
    pub fn new_with_members() {}
    pub fn propose_add_member() {}
    pub fn propose_remove_member() {}
    pub fn propose_self_update() {}
    pub fn commit_pending_proposals() {}
    pub fn get_pending_proposals() {}

    pub fn send_application_message() {}

    pub fn get_members(&self) -> Vec<Credential> {
        let mut members = Vec::new();
        for i in 0..self.group.get_tree().leaf_count().as_usize() {
            let node = self.group.get_tree().nodes[NodeIndex::from(i).as_usize()].clone();
            let credential = node.key_package.unwrap().get_credential().clone();
            members.push(credential);
        }
        members
    }
}

pub enum GroupError {
    Codec(CodecError),
}

impl From<CodecError> for GroupError {
    fn from(err: CodecError) -> GroupError {
        GroupError::Codec(err)
    }
}
