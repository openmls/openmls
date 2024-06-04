//! This benchmarks tests the performance of group operations in a large group
//! when the tree is fully populated.
//!
//! In particular do we assume that each member commits after joining the group.
//!
//! ## Measurements
//!
//! |                | 2      | 3      | 4      | 5      | 10     | 25      | 50      | 100      | 200      | 500       |
//! | -------------- | ------ | ------ | ------ | ------ | ------ | ------- | ------- | -------- | -------- | --------- |
//! | Adder          | 613 μs | 935 μs | 680 μs | 711 μs | 901 μs | 1.40 ms | 3.18 ms | 9.97 ms  | 39.80 ms | 260.49 ms |
//! | Updater        | 308 μs | 510 μs | 496 μs | 595 μs | 748 μs | 1.32 ms | 3.01 ms | 10.47 ms | 39.99 ms | 249.49 ms |
//! | Remover        | 193 μs | 305 μs | 320 μs | 474 μs | 698 μs | 1.23 ms | 3.10 ms | 10.07 ms | 38.10 ms | 257.24 ms |
//! | Process update | 303 μs | 433 μs | 429 μs | 529 μs | 698 μs | 1.16 ms | 2.86 ms | 9.61 ms  | 35.27 ms | 249.96 ms |

use std::{
    collections::HashMap,
    fs::File,
    time::{Duration, Instant},
};

use clap::Parser;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{MlsGroup, MlsGroupCreateConfig, StagedWelcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    prelude::LeafNodeIndex,
    prelude_test::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Member {
    provider: OpenMlsRustCrypto,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableStore {
    values: HashMap<String, String>,
}

impl Member {
    fn serialize(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let storage = self.provider.storage();

        let mut serializable_storage = SerializableStore::default();
        for (key, value) in &*storage.values.read().unwrap() {
            serializable_storage
                .values
                .insert(base64::encode(key), base64::encode(value));
        }

        (
            serde_json::to_vec(&serializable_storage).unwrap(),
            serde_json::to_vec(&self.credential_with_key).unwrap(),
            serde_json::to_vec(&self.signer).unwrap(),
        )
    }

    fn load(storage: &[u8], ckey: &[u8], signer: &[u8]) -> Self {
        let serializable_storage: SerializableStore = serde_json::from_slice(storage).unwrap();
        let credential_with_key: CredentialWithKey = serde_json::from_slice(ckey).unwrap();
        let signer: SignatureKeyPair = serde_json::from_slice(signer).unwrap();

        let provider = OpenMlsRustCrypto::default();
        let mut ks_map = provider.storage().values.write().unwrap();
        for (key, value) in serializable_storage.values {
            ks_map.insert(base64::decode(key).unwrap(), base64::decode(value).unwrap());
        }
        drop(ks_map);

        Self {
            provider,
            credential_with_key,
            signer,
        }
    }
}

#[inline(always)]
fn process_commit(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    commit: openmls::prelude::MlsMessageOut,
) {
    let processed_message = group
        .process_message(provider, commit.into_protocol_message().unwrap())
        .unwrap();

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        group.merge_staged_commit(provider, *staged_commit).unwrap();
    } else {
        unreachable!("Expected a StagedCommit.");
    }
}

#[inline(always)]
fn self_update(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
) -> MlsMessageOut {
    let (commit, _, _group_info) = group.self_update(provider, signer).unwrap();

    group.merge_pending_commit(provider).unwrap();

    commit
}

/// Remove member 1
#[inline(always)]
fn remove_member(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
) -> MlsMessageOut {
    let (commit, _, _group_info) = group
        .remove_members(provider, signer, &[LeafNodeIndex::new(1)])
        .unwrap();

    group.merge_pending_commit(provider).unwrap();

    commit
}

/// Create a new member
fn new_member(
    name: &str,
) -> (
    OpenMlsRustCrypto,
    SignatureKeyPair,
    CredentialWithKey,
    openmls::prelude::KeyPackageBundle,
) {
    let member_provider = OpenMlsRustCrypto::default();
    let credential = BasicCredential::new(name.into());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let key_package = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &member_provider,
            &signer,
            credential_with_key.clone(),
        )
        .expect("An unexpected error occurred.");
    (member_provider, signer, credential_with_key, key_package)
}

#[inline(always)]
fn add_member(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    key_package: KeyPackage,
) -> MlsMessageOut {
    let (commit, _welcome, _) = group.add_members(provider, signer, &[key_package]).unwrap();

    group.merge_pending_commit(provider).unwrap();

    commit
}

use generate::CIPHERSUITE;

mod generate {
    use super::*;

    pub const GROUP_SIZES: &[usize] = &[2, 3, 4, 5, 10, 25, 50, 100, 200, 500, 1000];
    // const GROUP_SIZES: &[usize] = &[2, 3, 4, 5, 10, 25, 50, 100];
    // const GROUP_SIZES: &[usize] = &[100, 200];
    pub const CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    /// Create a group of `num` clients.
    /// All of them committed after joining.
    pub fn setup(num: usize) -> Vec<(MlsGroup, Member)> {
        let creator_provider = OpenMlsRustCrypto::default();
        let creator_credential = BasicCredential::new(format!("Creator").into());
        let creator_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        let creator_credential_with_key = CredentialWithKey {
            credential: creator_credential.into(),
            signature_key: creator_signer.to_public_vec().into(),
        };

        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(CIPHERSUITE)
            .build();

        // Create the group
        let creator_group = MlsGroup::new(
            &creator_provider,
            &creator_signer,
            &mls_group_create_config,
            creator_credential_with_key.clone(),
        )
        .expect("An unexpected error occurred.");

        let mut members: Vec<(MlsGroup, Member)> = vec![(
            creator_group,
            Member {
                provider: creator_provider,
                credential_with_key: creator_credential_with_key,
                signer: creator_signer,
            },
        )];

        for member_i in 0..num - 1 {
            let (member_provider, signer, credential_with_key, key_package) =
                new_member(&format!("Member {member_i}"));

            let creator = &mut members[0];
            let creator_group = &mut creator.0;
            let creator_provider = &creator.1.provider;
            let creator_signer = &creator.1.signer;
            let (commit, welcome, _) = creator_group
                .add_members(
                    creator_provider,
                    creator_signer,
                    &[key_package.key_package().clone()],
                )
                .unwrap();

            creator_group
                .merge_pending_commit(creator_provider)
                .expect("error merging pending commit");

            let welcome: MlsMessageIn = welcome.into();
            let welcome = welcome
                .into_welcome()
                .expect("expected the message to be a welcome message");
            let mut member_i_group = StagedWelcome::new_from_welcome(
                &member_provider,
                mls_group_create_config.join_config(),
                welcome,
                Some(creator_group.export_ratchet_tree().into()),
            )
            .unwrap()
            .into_group(&member_provider)
            .unwrap();

            // Merge commit on all other members
            for (group, member) in members.iter_mut().skip(1) {
                process_commit(group, &member.provider, commit.clone());
            }

            // The new member commits and everyone else processes it.
            let update_commit = self_update(&mut member_i_group, &member_provider, &signer);
            for (group, member) in members.iter_mut() {
                process_commit(group, &member.provider, update_commit.clone());
            }

            // Add new member to list
            members.push((
                member_i_group,
                Member {
                    provider: member_provider,
                    credential_with_key,
                    signer,
                },
            ));
        }

        members
    }
}

const ITERATIONS: usize = 1000;
const WARMUP_ITERATIONS: usize = 5;

/// A custom benchmarking function.
fn bench<I, O, S, SI, R>(si: SI, mut setup: S, mut routine: R) -> Duration
where
    SI: Clone,
    S: FnMut(SI) -> I,
    R: FnMut(I) -> O,
{
    let mut time = Duration::ZERO;

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let input = setup(si.clone());
        routine(input);
    }

    // Benchmark
    for _ in 0..ITERATIONS {
        let input = setup(si.clone());

        let start = Instant::now();
        core::hint::black_box(routine(input));
        let end = Instant::now();

        time += end.duration_since(start);
    }

    time
}

#[derive(Parser)]
struct Args {
    #[clap(short, long, action)]
    write: bool,
}
mod util {
    use super::{generate, *};

    /// Read benchmark setups from the fiels previously written.
    pub fn read() -> Vec<Vec<(MlsGroup, Member)>> {
        let file = File::open("large-balanced-group-groups.json.gzip").unwrap();
        let mut reader = flate2::read::GzDecoder::new(file);
        let groups: Vec<Vec<MlsGroup>> = serde_json::from_reader(&mut reader).unwrap();

        let file = File::open("large-balanced-group-members.json.gzip").unwrap();
        let mut reader = flate2::read::GzDecoder::new(file);
        let members: Vec<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>> =
            serde_json::from_reader(&mut reader).unwrap();

        let members: Vec<Vec<Member>> = members
            .into_iter()
            .map(|members| {
                members
                    .into_iter()
                    .map(|m| Member::load(&m.0, &m.1, &m.2))
                    .collect()
            })
            .collect();

        let mut out = vec![];
        for (g, m) in groups.into_iter().zip(members.into_iter()) {
            out.push(g.into_iter().zip(m.into_iter()).collect())
        }

        out
    }

    /// Generate benchmark setups and write them out.
    pub fn write() {
        let mut groups = vec![];
        let mut members = vec![];

        println!("Writing groups for benchmarks ...");
        for num in generate::GROUP_SIZES {
            println!("Generating group of size {num} ...");
            // Generate and write out groups.
            let new_groups = generate::setup(*num);
            let (new_groups, new_members): (Vec<MlsGroup>, Vec<Member>) =
                new_groups.into_iter().unzip();
            let new_members: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> =
                new_members.into_iter().map(|m| m.serialize()).collect();
            groups.push(new_groups);
            members.push(new_members);
        }
        let file = File::create("large-balanced-group-groups.json.gzip").unwrap();
        let mut writer = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        serde_json::to_writer(&mut writer, &groups).unwrap();
        let file = File::create("large-balanced-group-members.json.gzip").unwrap();
        let mut writer = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        serde_json::to_writer(&mut writer, &members).unwrap();

        println!("Wrote new test groups to file.");
    }
}
use util::*;

fn print_time(label: &str, d: Duration) {
    let micros = d.as_micros();
    let time = if micros < (1_000 * ITERATIONS as u128) {
        format!("{} μs", micros / ITERATIONS as u128)
    } else if micros < (1_000_000 * ITERATIONS as u128) {
        format!(
            "{:.2} ms",
            (micros as f64 / (1_000_f64 * ITERATIONS as f64))
        )
    } else {
        format!(
            "{:.2}s",
            (micros as f64 / (1_000_000_f64 * ITERATIONS as f64))
        )
    };
    let space = if label.len() < 6 {
        format!("\t\t")
    } else {
        format!("\t")
    };

    println!("{label}:{space}{time}");
}

fn main() {
    let args = Args::parse();

    if args.write {
        // Only generate groups and write them out.
        write();

        return;
    }

    let all_groups = read();
    for groups in all_groups {
        if groups.len() != 10 {
            continue;
        }
        println!("{} Members", groups.len());

        // Add
        let time = bench(
            groups.clone(),
            |groups| {
                let (_member_provider, _signer, _credential_with_key, key_package) =
                    new_member(&format!("New Member"));
                let key_package = key_package.key_package().clone();

                (groups, key_package)
            },
            |(mut groups, key_package)| {
                let (updater_group, updater) = &mut groups[1];
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = add_member(updater_group, provider, signer, key_package);
            },
        );
        print_time("Adder", time);

        // Update
        let time = bench(
            groups.clone(),
            |groups| groups,
            |mut groups| {
                // Let group 1 update and merge the commit.
                let (updater_group, updater) = &mut groups[1];
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = self_update(updater_group, provider, signer);
            },
        );
        print_time("Updater", time);

        // Remove
        let time = bench(
            groups.clone(),
            |groups| groups,
            |mut groups| {
                // Let group 1 update and merge the commit.
                let (updater_group, updater) = &mut groups[0];
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = remove_member(updater_group, provider, signer);
            },
        );
        print_time("Remover", time);

        // Process an update
        let time = bench(
            groups,
            |mut groups| {
                // Let group 1 update and merge the commit.
                let (updater_group, updater) = &mut groups[1];
                let provider = &updater.provider;
                let signer = &updater.signer;
                let commit = self_update(updater_group, provider, signer);

                (groups, commit)
            },
            |(mut groups, commit)| {
                // Apply the commit at member 0
                let (member_group, member) = &mut groups[0];
                let provider = &member.provider;

                process_commit(member_group, provider, commit);
            },
        );
        print_time("Process update", time);

        println!("");
    }
}
