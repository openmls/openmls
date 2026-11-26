//! Random sequences of group operations, checked after every epoch against a
//! membership model and an RFC 9420 tree-shape model.
//!
//! The test is ignored by default. Run it with
//! `cargo test -p openmls --release random_group_operations -- --ignored`.
//!
//! Each run is driven by a seed, which alone determines the sequence of
//! operations. A failing run prints its seed and the operations it performed.
//! Environment variables:
//!
//! - `OPENMLS_RANDOM_GROUP_OPS_SEED=<u64>` replays a single seed.
//! - `OPENMLS_RANDOM_GROUP_OPS_DURATION_SECS=<u64>` runs consecutive seeds,
//!   starting at a random one, until the time is up.
//! - Without either, the test runs a few fixed seeds.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use openmls_test::openmls_test;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use rand::{rngs::StdRng, seq::IndexedRandom, RngExt, SeedableRng};
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{
    binary_tree::LeafNodeIndex,
    credentials::Credential,
    framing::{
        MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent, PublicMessageIn,
    },
    group::{
        tests_and_kats::utils::{
            generate_credential_with_key, minimal_capabilities_for, CredentialWithKeyAndSigner,
        },
        MlsGroup, MlsGroupJoinConfig, StagedWelcome, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    messages::proposals::ProposalType,
    prelude::Capabilities,
    treesync::LeafNodeParameters,
};

const SEED_ENV_VAR: &str = "OPENMLS_RANDOM_GROUP_OPS_SEED";
const DURATION_ENV_VAR: &str = "OPENMLS_RANDOM_GROUP_OPS_DURATION_SECS";
const DEFAULT_SEEDS: std::ops::Range<u64> = 0..4;
const OPERATIONS_PER_SEED: usize = 1000;
const CLIENT_POOL_SIZE: usize = 40;
const MAX_MEMBERS: usize = 16;
const MAX_ADDS_OR_REMOVES_PER_COMMIT: usize = 3;

#[openmls_test]
#[ignore = "long-running randomized test, run nightly or with --ignored"]
fn random_group_operations() {
    if let Some(seed) = env_u64(SEED_ENV_VAR) {
        run_seed::<Provider>(ciphersuite, seed);
    } else if let Some(duration) = env_u64(DURATION_ENV_VAR) {
        let deadline = Instant::now() + Duration::from_secs(duration);
        let first_seed: u64 = rand::rng().random();
        let mut seed = first_seed;
        while Instant::now() < deadline {
            run_seed::<Provider>(ciphersuite, seed);
            seed = seed.wrapping_add(1);
        }
        println!(
            "ran {} seeds starting at {first_seed}",
            seed.wrapping_sub(first_seed)
        );
    } else {
        for seed in DEFAULT_SEEDS {
            run_seed::<Provider>(ciphersuite, seed);
        }
    }
}

fn run_seed<Provider: OpenMlsProvider + Default>(ciphersuite: Ciphersuite, seed: u64) {
    let mut driver = Driver::<Provider>::new(ciphersuite, seed);
    for _ in 0..OPERATIONS_PER_SEED {
        driver.random_operation();
    }
}

fn env_u64(name: &str) -> Option<u64> {
    let value = std::env::var(name).ok()?;
    Some(
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a u64, got {value:?}")),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClientId(usize);

/// The leaves of the group's tree as RFC 9420 defines them, with the client
/// that should sit at each leaf.
struct TreeModel {
    leaves: Vec<Option<ClientId>>,
}

impl TreeModel {
    /// Applies a commit's removals and additions in the order of RFC 9420
    /// §12.3. A Remove blanks the leaf and then truncates the tree (§12.1.3).
    /// An Add takes the leftmost blank leaf or extends the tree with an
    /// all-blank right subtree (§12.1.1, §7.7). An external joiner is placed
    /// like an Add (§12.4.3.2).
    fn apply(&mut self, removed: &[LeafNodeIndex], added: &[ClientId]) {
        for leaf in removed {
            let slot = &mut self.leaves[leaf.usize()];
            assert!(slot.is_some(), "model removes blank leaf {leaf:?}");
            *slot = None;
            self.truncate();
        }
        for &client in added {
            self.add(client);
        }
    }

    fn truncate(&mut self) {
        while self.leaves.len() > 1
            && self.leaves[self.leaves.len() / 2..]
                .iter()
                .all(Option::is_none)
        {
            self.leaves.truncate(self.leaves.len() / 2);
        }
    }

    fn add(&mut self, client: ClientId) {
        let index = match self.leaves.iter().position(Option::is_none) {
            Some(index) => index,
            None => {
                let index = self.leaves.len();
                self.leaves.resize(index * 2, None);
                index
            }
        };
        self.leaves[index] = Some(client);
    }

    fn members(&self) -> Vec<(LeafNodeIndex, ClientId)> {
        let mut members = Vec::new();
        for (index, slot) in self.leaves.iter().enumerate() {
            if let Some(client) = slot {
                members.push((LeafNodeIndex::new(index as u32), *client));
            }
        }
        members
    }

    fn leaf_of(&self, client: ClientId) -> LeafNodeIndex {
        let index = self
            .leaves
            .iter()
            .position(|slot| *slot == Some(client))
            .unwrap_or_else(|| panic!("{client:?} is not in the model"));
        LeafNodeIndex::new(index as u32)
    }

    fn client_at(&self, leaf: LeafNodeIndex) -> ClientId {
        self.leaves[leaf.usize()].unwrap_or_else(|| panic!("model leaf {leaf:?} is blank"))
    }
}

/// A client's current state in the group. A resync replaces it with a fresh
/// provider.
struct Instance<Provider> {
    provider: Provider,
    group: MlsGroup,
}

enum PendingProposal<Provider> {
    SelfRemove {
        leaf: LeafNodeIndex,
        message: PublicMessageIn,
    },
    Remove {
        leaf: LeafNodeIndex,
    },
    Add {
        client: ClientId,
        joiner_provider: Provider,
    },
}

/// An operation returns false without changing anything if its
/// preconditions don't hold in the current state.
type Operation<Provider> = fn(&mut Driver<Provider>) -> bool;

struct Driver<Provider: OpenMlsProvider> {
    seed: u64,
    rng: StdRng,
    ciphersuite: Ciphersuite,
    capabilities: Capabilities,
    join_config: MlsGroupJoinConfig,
    clients: Vec<CredentialWithKeyAndSigner>,
    instances: BTreeMap<ClientId, Instance<Provider>>,
    pending: Vec<PendingProposal<Provider>>,
    model: TreeModel,
    log: Vec<String>,
}

impl<Provider: OpenMlsProvider> Drop for Driver<Provider> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "random_group_operations failed with seed {} ({SEED_ENV_VAR}={} replays it)",
                self.seed, self.seed
            );
            eprintln!("operations:");
            for entry in &self.log {
                eprintln!("  {entry}");
            }
        }
    }
}

impl<Provider: OpenMlsProvider + Default> Driver<Provider> {
    fn new(ciphersuite: Ciphersuite, seed: u64) -> Self {
        // The signers are passed around directly, so the provider they are
        // stored in is not used again.
        let key_store = Provider::default();
        let mut clients = Vec::new();
        for index in 0..CLIENT_POOL_SIZE {
            clients.push(generate_credential_with_key(
                format!("client-{index}").into_bytes(),
                ciphersuite.signature_algorithm(),
                &key_store,
            ));
        }

        // SelfRemove proposals have to be public messages to be committed by
        // an external joiner.
        let capabilities = minimal_capabilities_for(ciphersuite)
            .proposals(vec![ProposalType::SelfRemove])
            .build();
        let join_config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();

        let creator = ClientId(0);
        let provider = Provider::default();
        let group = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(capabilities.clone())
            .build(
                &provider,
                &clients[creator.0].signer,
                clients[creator.0].credential_with_key.clone(),
            )
            .unwrap();

        let mut driver = Self {
            seed,
            rng: StdRng::seed_from_u64(seed),
            ciphersuite,
            capabilities,
            join_config,
            clients,
            instances: BTreeMap::from([(creator, Instance { provider, group })]),
            pending: Vec::new(),
            model: TreeModel {
                leaves: vec![Some(creator)],
            },
            log: vec![format!("{creator:?} creates the group")],
        };
        driver.check_epoch();
        driver
    }

    fn random_operation(&mut self) {
        let operations: [(Operation<Provider>, u32); 7] = [
            (Self::self_update, 1),
            (Self::member_commit, 4),
            (Self::propose_self_remove, 1),
            (Self::propose_remove, 1),
            (Self::propose_add, 1),
            (Self::external_join, 1),
            (Self::resync, 1),
        ];
        loop {
            let (operation, _) = operations
                .choose_weighted(&mut self.rng, |(_, weight)| *weight)
                .unwrap();
            if operation(self) {
                return;
            }
        }
    }

    // Operations.

    fn self_update(&mut self) -> bool {
        let Some(committer) = self.random_committer() else {
            return false;
        };
        self.log
            .push(format!("{committer:?} commits a self-update"));
        let instance = self.instances.get_mut(&committer).unwrap();
        let bundle = instance
            .group
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .load_psks(instance.provider.storage())
            .unwrap()
            .build(
                instance.provider.rand(),
                instance.provider.crypto(),
                &self.clients[committer.0].signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&instance.provider)
            .unwrap();
        instance
            .group
            .merge_pending_commit(&instance.provider)
            .unwrap();

        self.pending.clear();
        self.deliver_commit(committer, bundle.commit());
        self.check_epoch();
        true
    }

    /// A member commits all pending proposals together with inline Removes,
    /// Adds, or both.
    fn member_commit(&mut self) -> bool {
        let Some(committer) = self.random_committer() else {
            return false;
        };

        let mut removable = self.members_not_pending_removal();
        removable.retain(|leaf| self.model.client_at(*leaf) != committer);
        let removals = self
            .rng
            .random_range(0..=removable.len().min(MAX_ADDS_OR_REMOVES_PER_COMMIT));
        let mut removed = Vec::new();
        for _ in 0..removals {
            let leaf = self.pick_biased_right(&removable);
            removable.retain(|candidate| *candidate != leaf);
            removed.push(leaf);
        }

        let mut joinable = self.joinable_clients();
        let size_after_commit =
            self.instances.len() - removed.len() - self.pending_removals().len()
                + self.pending_adds().len();
        let room = MAX_MEMBERS - size_after_commit;
        let adds = self
            .rng
            .random_range(0..=joinable.len().min(room).min(MAX_ADDS_OR_REMOVES_PER_COMMIT));
        let mut added = Vec::new();
        for _ in 0..adds {
            let client = joinable.remove(self.rng.random_range(0..joinable.len()));
            added.push(client);
        }

        let force_self_update = self.rng.random_bool(0.5);
        self.log.push(format!(
            "{committer:?} commits removes {removed:?}, adds {added:?}, {} pending proposals, \
             force_self_update {force_self_update}",
            self.pending.len(),
        ));

        let mut joiner_providers = BTreeMap::new();
        let mut key_packages = Vec::new();
        for &client in &added {
            let joiner_provider = Provider::default();
            key_packages.push(self.key_package(client, &joiner_provider));
            joiner_providers.insert(client, joiner_provider);
        }

        let instance = self.instances.get_mut(&committer).unwrap();
        let bundle = instance
            .group
            .commit_builder()
            .propose_removals(removed.iter().copied())
            .propose_adds(key_packages)
            .force_self_update(force_self_update)
            .load_psks(instance.provider.storage())
            .unwrap()
            .build(
                instance.provider.rand(),
                instance.provider.crypto(),
                &self.clients[committer.0].signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&instance.provider)
            .unwrap();

        // The committer chooses the order of the Add proposals in the commit,
        // and receivers apply them in that order.
        let mut add_order = Vec::new();
        for add in instance.group.pending_commit().unwrap().add_proposals() {
            let credential = add.add_proposal().key_package().leaf_node().credential();
            add_order.push(client_of(&self.clients, credential));
        }
        instance
            .group
            .merge_pending_commit(&instance.provider)
            .unwrap();

        for proposal in self.pending.drain(..) {
            match proposal {
                PendingProposal::SelfRemove { leaf, .. } | PendingProposal::Remove { leaf } => {
                    removed.push(leaf)
                }
                PendingProposal::Add {
                    client,
                    joiner_provider,
                } => {
                    added.push(client);
                    joiner_providers.insert(client, joiner_provider);
                }
            }
        }
        added.sort();
        let mut committed_adds = add_order.clone();
        committed_adds.sort();
        assert_eq!(committed_adds, added, "commit adds the wrong clients");

        for leaf in &removed {
            let client = self.model.client_at(*leaf);
            self.instances.remove(&client);
        }
        self.model.apply(&removed, &add_order);
        self.deliver_commit(committer, bundle.commit());

        if let Some(welcome) = bundle.to_welcome_msg() {
            let MlsMessageBodyIn::Welcome(welcome) = roundtrip(&welcome).extract() else {
                panic!("expected a Welcome");
            };
            for (client, provider) in joiner_providers {
                let group = StagedWelcome::new_from_welcome(
                    &provider,
                    &self.join_config,
                    welcome.clone(),
                    None,
                )
                .unwrap()
                .into_group(&provider)
                .unwrap();
                self.instances.insert(client, Instance { provider, group });
            }
        } else {
            assert!(
                joiner_providers.is_empty(),
                "commit with adds has no Welcome"
            );
        }

        self.check_epoch();
        true
    }

    /// A member, biased to the right edge of the tree, proposes to leave. A
    /// later member commit or external commit may cover the proposal.
    fn propose_self_remove(&mut self) -> bool {
        let removable = self.members_not_pending_removal();
        if removable.is_empty() {
            return false;
        }
        let leaver_leaf = self.pick_biased_right(&removable);
        let leaver = self.model.client_at(leaver_leaf);
        self.log.push(format!("{leaver:?} proposes a SelfRemove"));
        let instance = self.instances.get_mut(&leaver).unwrap();
        let message = instance
            .group
            .leave_group_via_self_remove(&instance.provider, &self.clients[leaver.0].signer)
            .unwrap();
        let MlsMessageBodyIn::PublicMessage(public_message) = roundtrip(&message).extract() else {
            panic!("SelfRemove proposal is not a public message");
        };
        self.deliver_proposal(leaver, &message);
        self.pending.push(PendingProposal::SelfRemove {
            leaf: leaver_leaf,
            message: public_message,
        });
        true
    }

    /// A member proposes to remove another member. Only a later member commit
    /// can cover the proposal.
    fn propose_remove(&mut self) -> bool {
        let proposer = self.random_member();
        let proposer_leaf = self.model.leaf_of(proposer);
        let mut targets = self.members_not_pending_removal();
        targets.retain(|leaf| *leaf != proposer_leaf);
        if targets.is_empty() {
            return false;
        }
        let target = self.pick_biased_right(&targets);
        self.log
            .push(format!("{proposer:?} proposes to remove leaf {target:?}"));
        let instance = self.instances.get_mut(&proposer).unwrap();
        let (message, _) = instance
            .group
            .propose_remove_member(&instance.provider, &self.clients[proposer.0].signer, target)
            .unwrap();
        self.deliver_proposal(proposer, &message);
        self.pending.push(PendingProposal::Remove { leaf: target });
        true
    }

    /// A member proposes to add a client. Only a later member commit can
    /// cover the proposal.
    fn propose_add(&mut self) -> bool {
        if self.instances.len() + self.pending_adds().len() >= MAX_MEMBERS {
            return false;
        }
        let joinable = self.joinable_clients();
        let Some(&client) = joinable.choose(&mut self.rng) else {
            return false;
        };
        let proposer = self.random_member();
        self.log
            .push(format!("{proposer:?} proposes to add {client:?}"));
        let joiner_provider = Provider::default();
        let key_package = self.key_package(client, &joiner_provider);
        let instance = self.instances.get_mut(&proposer).unwrap();
        let (message, _) = instance
            .group
            .propose_add_member(
                &instance.provider,
                &self.clients[proposer.0].signer,
                &key_package,
            )
            .unwrap();
        self.deliver_proposal(proposer, &message);
        self.pending.push(PendingProposal::Add {
            client,
            joiner_provider,
        });
        true
    }

    /// A client outside the group joins with an external commit.
    fn external_join(&mut self) -> bool {
        let joinable = self.joinable_clients();
        let Some(&joiner) = joinable.choose(&mut self.rng) else {
            return false;
        };
        let (self_remove_leaves, self_removes) = self.random_pending_self_removes();
        if self.instances.len() - self_remove_leaves.len() >= MAX_MEMBERS {
            return false;
        }
        self.log.push(format!(
            "{joiner:?} joins externally, committing SelfRemoves of leaves {self_remove_leaves:?}"
        ));
        self.external_commit(joiner, self_remove_leaves, self_removes);
        true
    }

    /// A member rejoins with an external commit from a fresh provider and the
    /// same signature key, so the commit removes its prior leaf.
    fn resync(&mut self) -> bool {
        let mut members = Vec::new();
        for (leaf, _) in self.model.members() {
            members.push(leaf);
        }
        let prior_leaf = self.pick_biased_right(&members);
        let client = self.model.client_at(prior_leaf);
        let (mut removed, self_removes) = self.random_pending_self_removes();
        self.log.push(format!(
            "{client:?} resyncs from leaf {prior_leaf:?}, committing SelfRemoves of leaves \
             {removed:?}"
        ));
        if !removed.contains(&prior_leaf) {
            removed.push(prior_leaf);
        }
        self.external_commit(client, removed, self_removes);
        true
    }

    /// `removed` lists every leaf the commit removes, including the joiner's
    /// prior leaf for a resync.
    fn external_commit(
        &mut self,
        joiner: ClientId,
        removed: Vec<LeafNodeIndex>,
        self_removes: Vec<PublicMessageIn>,
    ) {
        let exporter = self.random_member();
        let exporter_instance = &self.instances[&exporter];
        let group_info = roundtrip(
            &exporter_instance
                .group
                .export_group_info(
                    exporter_instance.provider.crypto(),
                    &self.clients[exporter.0].signer,
                    true,
                )
                .unwrap(),
        )
        .into_verifiable_group_info()
        .unwrap();

        let provider = Provider::default();
        let client = &self.clients[joiner.0];
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_proposals(self_removes)
            .with_config(self.join_config.clone())
            .build_group(&provider, group_info, client.credential_with_key.clone())
            .unwrap()
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(self.capabilities.clone())
                    .build(),
            )
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &client.signer, |_| true)
            .unwrap()
            .finalize(&provider)
            .unwrap();

        self.pending.clear();
        for leaf in &removed {
            let client = self.model.client_at(*leaf);
            self.instances.remove(&client);
        }
        self.model.apply(&removed, &[joiner]);
        self.deliver_commit(joiner, bundle.commit());
        self.instances.insert(joiner, Instance { provider, group });
        self.check_epoch();
    }

    // Message delivery.

    fn deliver_proposal(&mut self, sender: ClientId, message: &MlsMessageOut) {
        for (&client, instance) in self.instances.iter_mut() {
            if client == sender {
                continue;
            }
            let ProcessedMessageContent::ProposalMessage(proposal) =
                receive(client, instance, message)
            else {
                panic!("{client:?} expected a proposal");
            };
            instance
                .group
                .store_pending_proposal(instance.provider.storage(), *proposal)
                .unwrap();
        }
    }

    /// Delivers a commit to every member in the new epoch except `sender`.
    /// Members removed by the commit have already been dropped.
    fn deliver_commit(&mut self, sender: ClientId, message: &MlsMessageOut) {
        for (&client, instance) in self.instances.iter_mut() {
            if client == sender {
                continue;
            }
            let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                receive(client, instance, message)
            else {
                panic!("{client:?} expected a commit");
            };
            instance
                .group
                .merge_staged_commit(&instance.provider, *staged_commit)
                .unwrap();
        }
    }

    // Oracles.

    fn check_epoch(&mut self) {
        let expected_members = self.model.members();
        let mut expected_clients = Vec::new();
        for (_, client) in &expected_members {
            expected_clients.push(*client);
        }
        expected_clients.sort();
        assert_eq!(
            self.instances.keys().copied().collect::<Vec<_>>(),
            expected_clients,
            "driver state and model disagree on who is a member"
        );

        for (&client, instance) in &self.instances {
            self.check_tree_shape(client, &instance.group);

            let mut members = Vec::new();
            for member in instance.group.members() {
                members.push((member.index, client_of(&self.clients, &member.credential)));
            }
            assert_eq!(
                members, expected_members,
                "{client:?} has the wrong members"
            );
            assert_eq!(
                instance.group.own_leaf_index(),
                self.model.leaf_of(client),
                "{client:?} is at the wrong leaf"
            );
        }

        let (first_client, first) = self.instances.iter().next().unwrap();
        let tree = first.group.export_ratchet_tree();
        let epoch_authenticator = first.group.epoch_authenticator().clone();
        let exporter_secret = export_secret(first);
        for (client, instance) in &self.instances {
            assert_eq!(
                instance.group.export_ratchet_tree(),
                tree,
                "{client:?} and {first_client:?} have different trees"
            );
            assert_eq!(
                instance.group.epoch_authenticator(),
                &epoch_authenticator,
                "{client:?} and {first_client:?} have different epoch authenticators"
            );
            assert_eq!(
                export_secret(instance),
                exporter_secret,
                "{client:?} and {first_client:?} export different secrets"
            );
        }

        self.check_application_messages();
    }

    /// Checks the group's leaves against the model. Also checks that every non-blank parent
    /// node covers a non-blank leaf and that its unmerged leaves are non-blank
    /// leaves below it.
    fn check_tree_shape(&self, client: ClientId, group: &MlsGroup) {
        let mut leaves = vec![None; group.treesync().leaves().len()];
        for (index, leaf) in group.treesync().full_leaves() {
            leaves[index.usize()] = Some(client_of(&self.clients, leaf.credential()));
        }
        for (index, (actual, expected)) in leaves.iter().zip(&self.model.leaves).enumerate() {
            if let (Some(holder), None) = (actual, expected) {
                panic!(
                    "{client:?}: leaf {index} should be blank but holds {holder:?} \
                     (expected leaves {:?})",
                    self.model.leaves
                );
            }
        }
        assert_eq!(
            leaves, self.model.leaves,
            "{client:?}: leaves differ from the model"
        );

        for (parent_index, parent) in group.treesync().full_parents() {
            // Parent i is node 2i + 1. A node at level k spans the 2^k
            // leaves whose leftmost is node node + 1 - 2^k.
            let node = 2 * parent_index.u32() + 1;
            let level = node.trailing_ones();
            let first_leaf = (node + 1 - (1 << level)) / 2;
            let covered = first_leaf..first_leaf + (1 << level);
            assert!(
                covered.clone().any(|leaf| leaves[leaf as usize].is_some()),
                "{client:?}: parent {parent_index:?} is non-blank but covers only blank leaves"
            );
            for unmerged in parent.unmerged_leaves() {
                assert!(
                    covered.contains(&unmerged.u32()) && leaves[unmerged.usize()].is_some(),
                    "{client:?}: parent {parent_index:?} lists invalid unmerged leaf {unmerged:?}"
                );
            }
        }
    }

    fn check_application_messages(&mut self) {
        let senders: Vec<ClientId> = self.instances.keys().copied().collect();
        for sender in senders {
            let instance = self.instances.get_mut(&sender).unwrap();
            let payload =
                format!("epoch {:?} from {sender:?}", instance.group.epoch()).into_bytes();
            let message = instance
                .group
                .create_message(&instance.provider, &self.clients[sender.0].signer, &payload)
                .unwrap();
            for (&receiver, instance) in self.instances.iter_mut() {
                if receiver == sender {
                    continue;
                }
                let ProcessedMessageContent::ApplicationMessage(received) =
                    receive(receiver, instance, &message)
                else {
                    panic!("{receiver:?} expected an application message");
                };
                assert_eq!(received.into_bytes(), payload);
            }
        }
    }

    // Choices and lookups.

    fn random_member(&mut self) -> ClientId {
        let members: Vec<ClientId> = self.instances.keys().copied().collect();
        *members.choose(&mut self.rng).unwrap()
    }

    /// Returns a random member that can commit, that is, one that no pending
    /// proposal removes.
    fn random_committer(&mut self) -> Option<ClientId> {
        let candidates = self.members_not_pending_removal();
        let leaf = candidates.choose(&mut self.rng)?;
        Some(self.model.client_at(*leaf))
    }

    /// Returns members that no pending proposal removes yet.
    fn members_not_pending_removal(&self) -> Vec<LeafNodeIndex> {
        let removals = self.pending_removals();
        let mut removable = Vec::new();
        for (leaf, _) in self.model.members() {
            if !removals.contains(&leaf) {
                removable.push(leaf);
            }
        }
        removable
    }

    /// Returns clients that are neither members nor added by a pending
    /// proposal.
    fn joinable_clients(&self) -> Vec<ClientId> {
        let pending_adds = self.pending_adds();
        (0..CLIENT_POOL_SIZE)
            .map(ClientId)
            .filter(|client| !self.instances.contains_key(client) && !pending_adds.contains(client))
            .collect()
    }

    /// Picks the rightmost leaf half of the time and a uniformly random leaf
    /// otherwise, so that removals at the right edge and the truncations they
    /// cause happen often.
    fn pick_biased_right(&mut self, leaves: &[LeafNodeIndex]) -> LeafNodeIndex {
        if self.rng.random_bool(0.5) {
            *leaves.iter().max().unwrap()
        } else {
            *leaves.choose(&mut self.rng).unwrap()
        }
    }

    /// Takes each pending SelfRemove with probability one half. Returns the
    /// leaves they remove and the proposals.
    fn random_pending_self_removes(&mut self) -> (Vec<LeafNodeIndex>, Vec<PublicMessageIn>) {
        let mut leaves = Vec::new();
        let mut messages = Vec::new();
        for proposal in &self.pending {
            if let PendingProposal::SelfRemove { leaf, message } = proposal {
                if self.rng.random_bool(0.5) {
                    leaves.push(*leaf);
                    messages.push(message.clone());
                }
            }
        }
        (leaves, messages)
    }

    fn pending_removals(&self) -> Vec<LeafNodeIndex> {
        let mut removals = Vec::new();
        for proposal in &self.pending {
            match proposal {
                PendingProposal::SelfRemove { leaf, .. } | PendingProposal::Remove { leaf } => {
                    removals.push(*leaf)
                }
                PendingProposal::Add { .. } => {}
            }
        }
        removals
    }

    fn pending_adds(&self) -> Vec<ClientId> {
        let mut adds = Vec::new();
        for proposal in &self.pending {
            if let PendingProposal::Add { client, .. } = proposal {
                adds.push(*client);
            }
        }
        adds
    }

    fn key_package(&self, client: ClientId, provider: &Provider) -> KeyPackage {
        let client = &self.clients[client.0];
        KeyPackage::builder()
            .leaf_node_capabilities(self.capabilities.clone())
            .build(
                self.ciphersuite,
                provider,
                &client.signer,
                client.credential_with_key.clone(),
            )
            .unwrap()
            .key_package()
            .clone()
    }
}

fn client_of(clients: &[CredentialWithKeyAndSigner], credential: &Credential) -> ClientId {
    let index = clients
        .iter()
        .position(|client| client.credential_with_key.credential == *credential)
        .unwrap_or_else(|| panic!("unknown credential {credential:?}"));
    ClientId(index)
}

/// Processes `message` as `receiver` after a TLS round trip.
fn receive<Provider: OpenMlsProvider>(
    receiver: ClientId,
    instance: &mut Instance<Provider>,
    message: &MlsMessageOut,
) -> ProcessedMessageContent {
    instance
        .group
        .process_message(
            &instance.provider,
            roundtrip(message).try_into_protocol_message().unwrap(),
        )
        .unwrap_or_else(|error| panic!("{receiver:?} rejects a message: {error:?}"))
        .into_content()
}

fn roundtrip(message: &MlsMessageOut) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap()).unwrap()
}

fn export_secret<Provider: OpenMlsProvider>(instance: &Instance<Provider>) -> Vec<u8> {
    instance
        .group
        .export_secret(
            instance.provider.crypto(),
            "random group operations",
            &[],
            32,
        )
        .unwrap()
        .as_slice()
        .to_vec()
}
