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

use crate::client::*;
use crate::framing::*;
use crate::group::*;
use crate::key_packages::*;
use crate::messages::*;
pub trait Api {
    /// Create a new group.
    fn new(creator: Client, group_id: &[u8], ciphersuite_name: CiphersuiteName) -> Group;
    /// Join a group from a Welcome message
    // TODO: add support for Welcome Extensions
    fn new_from_welcome(
        joiner: Client,
        welcome: Welcome,
        ratchet_tree: RatchetTree,
        tree_hash: &[u8],
    ) -> Result<Group, WelcomeError>;

    // Create handshake messages

    /// Create an `AddProposal`
    fn create_add_proposal(
        &self,
        aad: &[u8],
        joiner_key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal);
    /// Create an `UpdateProposal`
    fn create_update_proposal(
        &self,
        aad: &[u8],
        key_package: KeyPackage,
    ) -> (MLSPlaintext, Proposal);
    /// Create a `RemoveProposal`
    fn create_remove_proposal(
        &self,
        aad: &[u8],
        removed_index: LeafIndex,
    ) -> (MLSPlaintext, Proposal);
    /// Create a `Commit` and an optional `Welcome`
    fn create_commit(
        &self,
        aad: &[u8],
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
        force_self_update: bool,
    ) -> (MLSPlaintext, Option<Welcome>);

    /// Apply a `Commit` message
    fn apply_commit(
        &mut self,
        mls_plaintext: MLSPlaintext,
        proposals: Vec<(Sender, Proposal)>,
        own_key_packages: Vec<(HPKEPrivateKey, KeyPackage)>,
    );

    /// Create application message
    fn create_application_message(&self, aad: &[u8], msg: &[u8]) -> MLSPlaintext;

    /// Encrypt an MLS message
    fn encrypt(&mut self, mls_plaintext: MLSPlaintext) -> MLSCiphertext;
    /// Decrypt an MLS message
    fn decrypt(&mut self, mls_ciphertext: MLSCiphertext) -> MLSPlaintext;

    // Exporter
    // TODO: add the label and implement the whole exporter
    fn get_exporter_secret(&self) -> Vec<u8>;

    // Validation
    fn validate_proposal(&self, proposal: Proposal) -> ProposalValidationResult;
    fn validate_commit(&self, commit: Commit) -> CommitValidationResult;
    fn validate_mls_plaintext(&self, mls_plaintext: MLSPlaintext) -> MlsPlaintextValidationResult;
    fn validate_proposal_against_policy(
        &self,
        proposal: Proposal,
    ) -> ProposalPolicyValidationResult;
    fn validate_commit_against_policy(
        &self,
        commit: Commit,
        proposals: Vec<Proposal>,
    ) -> CommitPolicyValidationResult;
}
