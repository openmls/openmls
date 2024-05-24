//! This benchmarks tests the performance of group operations in a large group
//! when the tree is fully populated.
//!
//! In particular do we assume that each member commits after joining the group.
//!
//! ## Measurements
//!
//! | Operation    | Time (2 Members) | Time (5 Members) | Time (10 Members) | Time (25 Members) |
//! | ------------ | ---------------- | ---------------- | ----------------- | ----------------- |
//! | Add          |                  |                  |                   |                   |
//! | Remove       |                  |                  |                   |                   |
//! | Update       |                  |                  |                   |                   |

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    time::{Duration, Instant},
};

use clap::{arg, command, Parser};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{MlsGroup, MlsGroupCreateConfig, StagedWelcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    prelude::LeafNodeIndex,
    prelude_test::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
struct Member {
    provider: OpenMlsRustCrypto,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
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

// const GROUP_SIZES: &[usize] = &[2, 3, 4, 5, 10, 25, 50, 100, 200, 500];
const GROUP_SIZES: &[usize] = &[3, 10];
// const GROUP_SIZES: &[usize] = &[100, 200];
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Create a group of `num` clients.
/// All of them committed after joining.
fn setup(num: usize) -> Vec<(MlsGroup, Member)> {
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

fn add(c: &mut Criterion) {
    let mut group = c.benchmark_group("Add");

    for group_size in GROUP_SIZES.iter() {
        group.bench_with_input(
            BenchmarkId::new("Adder", group_size),
            group_size,
            |b, group_size| {
                b.iter_batched(
                    || {
                        let groups = setup(*group_size);

                        let (_member_provider, _signer, _credential_with_key, key_package) =
                            new_member(&format!("New Member"));
                        (groups, key_package.key_package().clone())
                    },
                    |(mut groups, key_package)| {
                        add_bench(groups, key_package);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

/// Benchmarking the time for member 1 in the list of `groups` to add a new
/// member.
fn add_bench(mut groups: Vec<(MlsGroup, Member)>, key_package: KeyPackage) {
    // Let group 1 add a member and merge the commit.
    let (updater_group, updater) = &mut groups[1];
    let provider = &updater.provider;
    let signer = &updater.signer;
    let _ = add_member(updater_group, provider, signer, key_package);
}

fn remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("Remove");

    for group_size in GROUP_SIZES.iter() {
        group.bench_with_input(
            BenchmarkId::new("Remover", group_size),
            group_size,
            |b, group_size| {
                b.iter_batched(
                    || {
                        let groups = setup(*group_size);
                        groups
                    },
                    |mut groups| {
                        // Let group 1 update and merge the commit.
                        let (updater_group, updater) = &mut groups[0];
                        let provider = &updater.provider;
                        let signer = &updater.signer;
                        let _ = remove_member(updater_group, provider, signer);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn update(c: &mut Criterion) {
    let mut group = c.benchmark_group("Update");

    for group_size in GROUP_SIZES.iter() {
        group.bench_with_input(
            BenchmarkId::new("Updater", group_size),
            group_size,
            |b, group_size| {
                b.iter_batched(
                    || {
                        let groups = setup(*group_size);
                        groups
                    },
                    |mut groups| {
                        // Let group 1 update and merge the commit.
                        let (updater_group, updater) = &mut groups[1];
                        let provider = &updater.provider;
                        let signer = &updater.signer;
                        let _ = self_update(updater_group, provider, signer);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }

    for group_size in GROUP_SIZES.iter() {
        group.bench_with_input(
            BenchmarkId::new("Member", group_size),
            group_size,
            |b, group_size| {
                b.iter_batched(
                    || {
                        let mut groups = setup(*group_size);

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
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    add(c);
    // remove(c);
    // update(c);
}

// Criterion is super slow. So we're doing manual benchmarks here as well
// criterion_group!(benches, criterion_benchmark);
// criterion_main!(benches);

const ITERATIONS: usize = 10;
const WARMUP_ITERATIONS: usize = 1;

fn duration(d: Duration) -> f64 {
    ((d.as_secs() as f64) + (d.subsec_nanos() as f64 * 1e-9)) * 1000000f64
}

fn bench<I, O, S, R>(mut setup: S, mut routine: R) -> f64
where
    S: FnMut() -> I,
    R: FnMut(I) -> O,
{
    let mut time = 0f64;

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let input = setup();
        routine(input);
    }

    // Benchmark
    for _ in 0..ITERATIONS {
        let input = setup();

        let start = Instant::now();
        core::hint::black_box(routine(input));
        let end = Instant::now();

        time += duration(end.duration_since(start));
    }

    time
}

// #[derive(Parser, Debug)]
// #[command(version, about, long_about = None)]
// struct Args {
//     /// Write groups out.
//     #[arg(short, long, num_args = 0)]
//     write: Option<bool>,
// }

fn main() {
    // let args = Args::parse();

    let mut groups = vec![];

    if false {
        println!("Writing groups for benchmarks ...");
        for num in GROUP_SIZES {
            println!("Generating group of size {num} ...");
            // Generate and write out groups.
            let new_groups = setup(*num);
            // let (groups, members): (Vec<MlsGroup>, Vec<Member>) = new_groups.into_iter().unzip();
            // eprintln!("{:?}", serde_json::to_vec(&new_groups));
            groups.push(new_groups);
        }
        let file = File::create("large-balanced-group.json").unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &groups).unwrap();

        println!("Wrote new test groups to file.");
        return;
    }

    let file = File::open("large-balanced-group.json").unwrap();
    let mut reader = BufReader::new(file);
    let groups: Vec<Vec<(MlsGroup, Member)>> = serde_json::from_reader(&mut reader).unwrap();

    // for num in GROUP_SIZES {
    //     println!("{num} Members");

    //     // Add
    //     let time = bench(
    //         || {
    //             let groups = setup(*num);
    //             let (_member_provider, _signer, _credential_with_key, key_package) =
    //                 new_member(&format!("New Member"));
    //             let key_package = key_package.key_package().clone();

    //             (groups, key_package)
    //         },
    //         |(groups, key_package)| add_bench(groups, key_package),
    //     );
    //     println!("  Adder: {}μs", time / (ITERATIONS as f64));

    //     // Update
    //     let time = bench(
    //         || setup(*num),
    //         |groups| {
    //             bench_update(groups);
    //         },
    //     );
    //     println!("  Updater: {}μs", time / (ITERATIONS as f64));
    // }
}

fn bench_update(mut groups: Vec<(MlsGroup, Member)>) {
    // Let group 1 update and merge the commit.
    let (updater_group, updater) = &mut groups[1];
    let provider = &updater.provider;
    let signer = &updater.signer;
    let _ = self_update(updater_group, provider, signer);
}
