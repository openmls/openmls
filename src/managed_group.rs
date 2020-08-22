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
use crate::client::*;
use crate::codec::*;
use crate::creds::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
use crate::tree::*;

pub struct ManagedGroup {
    pub group: Group,
    pub generation: u32,
    pub plaintext_queue: Vec<MLSPlaintext>,
    pub public_queue: ProposalQueue,
    pub own_queue: ProposalQueue,
    pub pending_kpbs: Vec<KeyPackageBundle>,
}

impl ManagedGroup {
    pub fn new(client: Client, group_id: GroupId, ciphersuite_name: CiphersuiteName) -> Self {
        let group = Group::new(client, &group_id.as_slice(), ciphersuite_name);

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
        client: Client,
        welcome: Welcome,
        ratchet_tree: RatchetTree,
        tree_hash: &[u8],
        kpb: KeyPackageBundle,
    ) -> Result<ManagedGroup, WelcomeError> {
        let group = Group::new_from_welcome(client, welcome, ratchet_tree, tree_hash)?;
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
        let mut members = Vec::with_capacity(self.group.tree.leaf_count().as_usize());
        for i in 0..self.group.tree.leaf_count().as_usize() {
            let node =
                self.group.tree.nodes[NodeIndex::from(LeafIndex::from(i)).as_usize()].clone();
            let credential = node.key_package.unwrap().get_credential().clone();
            members.push(credential);
        }
        members
    }
    pub fn get_ciphersuite_name(&self) -> &Ciphersuite {
        self.group
            .client
            .get_ciphersuite(&self.group.ciphersuite_name)
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
