//! This benchmarks tests the performance of group operations in a large group
//! when the tree is fully populated.
//!
//! In particular do we assume that each member commits after joining the group.

use std::{
    collections::HashMap,
    fs::File,
    time::{Duration, Instant},
};

use base64::prelude::*;
use clap::Parser;
use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        GroupId, MlsGroup, MlsGroupCreateConfig, StagedWelcome, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    prelude::LeafNodeIndex,
    prelude_test::*,
    treesync::LeafNodeParameters,
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
    group_id: GroupId,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableStore {
    values: HashMap<String, String>,
}

impl Member {
    fn serialize(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let storage = self.provider.storage();

        let mut serializable_storage = SerializableStore::default();
        for (key, value) in &*storage.values.read().unwrap() {
            serializable_storage
                .values
                .insert(BASE64_STANDARD.encode(key), BASE64_STANDARD.encode(value));
        }

        (
            serde_json::to_vec(&serializable_storage).unwrap(),
            serde_json::to_vec(&self.credential_with_key).unwrap(),
            serde_json::to_vec(&self.signer).unwrap(),
            serde_json::to_vec(&self.group_id).unwrap(),
        )
    }

    fn load(storage: &[u8], ckey: &[u8], signer: &[u8], group_id: &[u8]) -> Self {
        let serializable_storage: SerializableStore = serde_json::from_slice(storage).unwrap();
        let credential_with_key: CredentialWithKey = serde_json::from_slice(ckey).unwrap();
        let signer: SignatureKeyPair = serde_json::from_slice(signer).unwrap();
        let group_id: GroupId = serde_json::from_slice(group_id).unwrap();

        let provider = OpenMlsRustCrypto::default();
        let mut ks_map = provider.storage().values.write().unwrap();
        for (key, value) in serializable_storage.values {
            ks_map.insert(
                BASE64_STANDARD.decode(key).unwrap(),
                BASE64_STANDARD.decode(value).unwrap(),
            );
        }
        drop(ks_map);

        Self {
            provider,
            credential_with_key,
            signer,
            group_id,
        }
    }

    fn group(&self) -> Option<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &self.group_id)
            .ok()
            .flatten()
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
    let commit = group
        .self_update(provider, signer, LeafNodeParameters::default())
        .unwrap()
        .into_commit();

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
    use indicatif::ProgressBar;

    use super::*;

    pub const GROUP_SIZES: &[usize] = &[2, 3, 4, 5, 10, 25, 50, 100];
    pub const CIPHERSUITE: Ciphersuite =
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    /// Create a group of `num` clients.
    /// All of them committed after joining.
    pub fn setup(
        num: usize,
        variant: Option<SetupVariants>,
        members: Option<(Vec<MlsGroup>, Vec<Member>)>,
    ) -> Vec<(MlsGroup, Member)> {
        // We default to a bare group unless variant wants something else.
        let variant = variant.unwrap_or(SetupVariants::Bare);

        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(CIPHERSUITE)
            .build();

        // If we have a previous group/member setup, let's use it.
        // The creator is always at 0.
        let mut members = if let Some(members) = members {
            members.0.into_iter().zip(members.1).collect()
        } else {
            // Create a new setup.
            let creator_provider = OpenMlsRustCrypto::default();
            let creator_credential = BasicCredential::new("Creator".to_string().into());
            let creator_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
            let creator_credential_with_key = CredentialWithKey {
                credential: creator_credential.into(),
                signature_key: creator_signer.to_public_vec().into(),
            };

            // Create the group
            let creator_group = MlsGroup::new(
                &creator_provider,
                &creator_signer,
                &mls_group_create_config,
                creator_credential_with_key.clone(),
            )
            .expect("An unexpected error occurred.");

            let group_id = creator_group.group_id().clone();

            vec![(
                creator_group,
                Member {
                    provider: creator_provider,
                    credential_with_key: creator_credential_with_key,
                    signer: creator_signer,
                    group_id,
                },
            )]
        };

        let pb = ProgressBar::new((num - members.len()) as u64);
        for member_i in members.len()..num {
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

            // Depending on the variant we do something here.
            match variant {
                SetupVariants::Bare => (), // Nothing to do in this case.
                SetupVariants::CommitAfterJoin => {
                    // The new member commits and everyone else processes it.
                    let update_commit = self_update(&mut member_i_group, &member_provider, &signer);
                    for (group, member) in members.iter_mut() {
                        process_commit(group, &member.provider, update_commit.clone());
                    }
                }
                SetupVariants::CommitToFullGroup => (), // Commit after everyone was added.
            }

            let group_id = member_i_group.group_id().clone();

            // Add new member to list
            members.push((
                member_i_group,
                Member {
                    provider: member_provider,
                    credential_with_key,
                    signer,
                    group_id,
                },
            ));
            pb.inc(1);
        }
        pb.finish();

        // Depending on the variant we do something once everyone was added.
        match variant {
            SetupVariants::Bare => (),            // Nothing to do in this case.
            SetupVariants::CommitAfterJoin => (), // Noting to do in this case.
            SetupVariants::CommitToFullGroup => {
                println!("Commit to the full group.");
                let pb = ProgressBar::new((num - members.len()) as u64);
                // Every member commits and everyone else processes it.
                for i in 0..members.len() {
                    let (member_i_group, member_i) = &mut members[i];
                    let update_commit =
                        self_update(member_i_group, &member_i.provider, &member_i.signer);
                    for (j, (group, member)) in members.iter_mut().enumerate() {
                        if i != j {
                            process_commit(group, &member.provider, update_commit.clone());
                        }
                    }
                }
                pb.finish();
            }
        }

        members
    }
}

const ITERATIONS: usize = 1000;
const WARMUP_ITERATIONS: usize = 5;

/// A custom benchmarking function.
///
/// DO NOT USE THIS WITH LARGE INPUTS
#[inline(always)]
#[allow(dead_code)]
fn bench<I, O, S, SI, R>(si: &SI, mut setup: S, mut routine: R) -> Duration
where
    SI: Clone,
    S: FnMut(&SI) -> I,
    R: FnMut(I) -> O,
{
    let mut time = Duration::ZERO;

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let input = setup(si);
        routine(input);
    }

    // Benchmark
    for _ in 0..ITERATIONS {
        let input = setup(si);

        let start = Instant::now();
        core::hint::black_box(routine(input));
        let end = Instant::now();

        time += end.duration_since(start);
    }

    time
}

// A benchmarking macro to avoid copying memory and skewing the results.
macro_rules! bench {
    ($groups:expr, $setup:expr, $routine:expr) => {{
        let mut time = Duration::ZERO;

        // Warmup
        for _ in 0..WARMUP_ITERATIONS {
            let input = $setup($groups);
            $routine(input);
        }

        // Benchmark
        for _ in 0..ITERATIONS {
            let input = $setup($groups);

            let start = Instant::now();
            core::hint::black_box($routine(input));
            let end = Instant::now();

            time += end.duration_since(start);
        }

        time
    }};
}

/// The different group setups for the benchmarks.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum SetupVariants {
    /// No messages are sent after the setup.
    Bare,

    /// Every member sends a commit directly after joining the group.
    CommitAfterJoin,

    /// Every member sends a commit after everyone was added to the group.
    CommitToFullGroup,
}

/// A tool to benchmark openmls (large) groups.
///
/// The benchmarks need to write a setup first that is then read to run the benchmarks.
#[derive(Parser)]
struct Args {
    /// Write out the setup (groups and states)
    #[clap(short, long, action)]
    write: bool,

    /// The file to read or write.
    #[clap(short, long)]
    data: Option<String>,

    /// The group sizes to run or generate.
    /// This has to be a list of values, separated by spaces, e.g. 2 3 5 10
    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    groups: Option<Vec<usize>>,

    /// The group setup to use.
    #[clap(short, long)]
    setup: Option<SetupVariants>,
}
mod util {
    use std::path::Path;

    use itertools::Itertools;

    use super::{generate, *};

    const MEMBERS_PATH: &str = "large-balanced-group-members.json.gzip";

    type Members = Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>;

    /// Read benchmark setups from the fiels previously written.
    pub fn read(path: Option<String>) -> Vec<Vec<(MlsGroup, Member)>> {
        let file = File::open(members_file(&path)).unwrap();
        let mut reader = flate2::read::GzDecoder::new(file);
        let members: Vec<Members> = serde_json::from_reader(&mut reader).unwrap();

        let members: Vec<Vec<(MlsGroup, Member)>> = members
            .into_iter()
            .map(|members| {
                members
                    .into_iter()
                    .map(|m| {
                        let m = Member::load(&m.0, &m.1, &m.2, &m.3);

                        (m.group().unwrap(), m)
                    })
                    .collect()
            })
            .collect();

        members
    }

    fn members_file(path: &Option<String>) -> std::path::PathBuf {
        let path = path.clone().unwrap_or_default();
        let path = Path::new(&path);
        path.join(MEMBERS_PATH)
    }

    /// Generate benchmark setups and write them out.
    pub fn write(
        path: Option<String>,
        group_sizes: Option<Vec<usize>>,
        variant: Option<SetupVariants>,
    ) {
        let mut members = vec![];

        let group_sizes = group_sizes.unwrap_or(generate::GROUP_SIZES.to_vec());
        println!("Generating groups for benchmarks {group_sizes:?}...");
        let mut smaller_groups = None;
        for num in group_sizes.into_iter().sorted() {
            println!("Generating group of size {num} ...");
            // Generate and write out groups.
            let new_groups = generate::setup(num, variant, smaller_groups);
            let (new_groups, new_members): (Vec<MlsGroup>, Vec<Member>) =
                new_groups.into_iter().unzip();
            smaller_groups = Some((new_groups.clone(), new_members.clone()));
            let new_members: Members = new_members.into_iter().map(|m| m.serialize()).collect();
            members.push(new_members);
        }

        println!("Writing out files.");
        let file = File::create(members_file(&path)).unwrap();
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
        "\t\t".to_string()
    } else {
        "\t".to_string()
    };

    println!("{label}:{space}{time}");
}

fn main() {
    let args = Args::parse();

    if args.write {
        // Only generate groups and write them out.
        write(args.data, args.groups, args.setup);

        return;
    }

    let all_groups = read(args.data);
    for groups in all_groups.iter() {
        if let Some(group_sizes) = &args.groups {
            // Only run the groups of the sizes from the cli
            if !group_sizes.contains(&groups.len()) {
                continue;
            }
        }
        println!("{} Members", groups.len());

        // Add
        let time = bench!(
            groups,
            |groups: &Vec<(MlsGroup, Member)>| {
                let (_member_provider, _signer, _credential_with_key, key_package) =
                    new_member("New Member");
                let key_package = key_package.key_package().clone();

                (groups[1].clone(), key_package)
            },
            |(group1, key_package): ((MlsGroup, Member), KeyPackage)| {
                let (mut updater_group, updater) = group1;
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = add_member(&mut updater_group, provider, signer, key_package);
            }
        );
        print_time("Adder", time);

        // Update
        let time = bench!(
            groups,
            |groups: &Vec<(MlsGroup, Member)>| groups[1].clone(),
            |group1: (MlsGroup, Member)| {
                // Let group 1 update and merge the commit.
                let (mut updater_group, updater) = group1;
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = self_update(&mut updater_group, provider, signer);
            }
        );
        print_time("Updater", time);

        // Remove
        let time = bench!(
            groups,
            |groups: &Vec<(MlsGroup, Member)>| groups[0].clone(),
            |group0: (MlsGroup, Member)| {
                // Let group 1 update and merge the commit.
                let (mut updater_group, updater) = group0;
                let provider = &updater.provider;
                let signer = &updater.signer;
                let _ = remove_member(&mut updater_group, provider, signer);
            }
        );
        print_time("Remover", time);

        // Process an update
        let time = bench!(
            groups,
            |groups: &Vec<(MlsGroup, Member)>| {
                // Let group 1 update and merge the commit.
                let (updater_group, updater) = &groups[1];
                let provider = &updater.provider;
                let signer = &updater.signer;
                let commit = self_update(&mut updater_group.clone(), provider, signer);

                (groups[0].clone(), commit)
            },
            |(group0, commit): ((MlsGroup, Member), MlsMessageOut)| {
                // Apply the commit at member 0
                let (mut member_group, member) = group0;
                let provider = &member.provider;

                process_commit(&mut member_group, provider, commit);
            }
        );
        print_time("Process update", time);
    }
}
