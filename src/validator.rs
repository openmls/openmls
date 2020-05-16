// Wire
// Copyright (C) 2020 Wire Swiss GmbH
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

use framing::*;
use group::*;
use messages::*;

pub struct Validator<'a, Group> {
    group: &'a Group,
}

impl<'a> Validator<'a, Group> {
    pub fn new(group: &'a Group) -> Self {
        Self { group }
    }
    pub fn validate_proposal(&self, proposal: &Proposal, _sender: Sender) -> bool {
        let members = self.group.roster();
        match proposal {
            Proposal::Add(add_proposal) => {
                let kp = add_proposal.key_package.clone();
                let credential = kp.credential.clone();
                let in_roster = members.iter().any(|m| m == &credential);
                if in_roster {
                    return false;
                }
                kp.self_verify()
            }
            Proposal::Update(update_proposal) => {
                let kp = update_proposal.key_package.clone();
                let credential = kp.credential.clone();
                let in_roster = members.iter().any(|m| m == &credential);
                if !in_roster {
                    return false;
                }
                kp.self_verify()
            }
            Proposal::Remove(remove_proposal) => {
                let removed = TreeIndex::from(remove_proposal.removed);
                if removed.as_usize() % 2 != 0 {
                    return false;
                }
                if removed >= self.group.tree.tree_size() {
                    return false;
                }
                if self.group.tree.nodes[removed.as_usize()].is_blank() {
                    return false;
                }
                true
            }
        }
    }
}
