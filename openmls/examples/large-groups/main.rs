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
use indicatif::ProgressBar;
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
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::SqliteStorageProvider;
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use rayon::iter::{
    IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

mod provider;
mod storage;

use provider::*;
use storage::*;

pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

const CHUNK_SIZE: usize = 4000;

// #[derive(Debug, Clone)]
pub struct Member {
    pub id: u64,
    pub provider: Provider,
    pub credential_with_key: CredentialWithKey,
    pub signer: SignatureKeyPair,
    pub group_id: Option<GroupId>,
}

impl Member {
    fn new(id: u64) -> (Self, openmls::prelude::KeyPackageBundle) {
        let provider = Provider::default();
        let credential = BasicCredential::new(format!("Member {id}").into());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        let key_package = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &signer, credential_with_key.clone())
            .expect("An unexpected error occurred.");

        let member = Member {
            id,
            provider,
            credential_with_key,
            signer,
            group_id: None,
        };
        (member, key_package)
    }

    fn group(&self) -> Option<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &self.group_id.as_ref().unwrap())
            .ok()
            .flatten()
    }
}

// #[derive(Debug, Clone)]
struct MemberWithGroup {
    member: Member,
    group: MlsGroup,
}

// impl MemberWithGroup {
//     fn new(member: Member, group: MlsGroup) -> Self {
//         Self { member, group }
//     }

//     fn write(&self, store: &Connection) {
//         let (storage, ckey, signer, group_id) = self.member.serialize();
//         // store
//         //     .execute(
//     }
// }

// #[derive(Debug, Default, Serialize, Deserialize)]
// struct SerializableStore {
//     values: HashMap<String, String>,
// }

// impl Member {
//     fn serialize(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
//         (
//             serde_json::to_vec(&self.credential_with_key).unwrap(),
//             serde_json::to_vec(&self.signer).unwrap(),
//             serde_json::to_vec(&self.group_id).unwrap(),
//         )
//     }

//     fn load(storage: &[u8], ckey: &[u8], signer: &[u8], group_id: &[u8]) -> Self {
//         let serializable_storage: SerializableStore = serde_json::from_slice(storage).unwrap();
//         let credential_with_key: CredentialWithKey = serde_json::from_slice(ckey).unwrap();
//         let signer: SignatureKeyPair = serde_json::from_slice(signer).unwrap();
//         let group_id: GroupId = serde_json::from_slice(group_id).unwrap();

//         let provider = Provider::default();
//         {
//             let mut ks_map = provider.storage().values.write().unwrap();
//             for (key, value) in serializable_storage.values {
//                 ks_map.insert(
//                     BASE64_STANDARD.decode(key).unwrap(),
//                     BASE64_STANDARD.decode(value).unwrap(),
//                 );
//             }
//         }

//         Self {
//             provider,
//             credential_with_key,
//             signer,
//             group_id,
//         }
//     }

//     fn group(&self) -> Option<MlsGroup> {
//         MlsGroup::load(self.provider.storage(), &self.group_id)
//             .ok()
//             .flatten()
//     }
// }

#[inline(always)]
fn process_commit(
    group: &mut MlsGroup,
    provider: &Provider,
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
    provider: &Provider,
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
    provider: &Provider,
    signer: &SignatureKeyPair,
) -> MlsMessageOut {
    let (commit, _, _group_info) = group
        .remove_members(provider, signer, &[LeafNodeIndex::new(1)])
        .unwrap();

    group.merge_pending_commit(provider).unwrap();

    commit
}

#[inline(always)]
fn add_member(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &SignatureKeyPair,
    key_package: KeyPackage,
) -> MlsMessageOut {
    let (commit, _welcome, _) = group.add_members(provider, signer, &[key_package]).unwrap();

    group.merge_pending_commit(provider).unwrap();

    commit
}

// use generate::CIPHERSUITE;

// mod generate {
//     use indicatif::ProgressBar;
//     use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

//     use super::*;

//     pub const GROUP_SIZES: &[usize] = &[2, 3, 4, 5, 10, 25, 50, 100];

/// Create a group of `num` clients.
/// All of them committed after joining.
fn setup(
    num: usize,
    max_members_in_chunk: usize,
    variant: Option<SetupVariants>,
    members: Option<(Vec<MlsGroup>, Vec<Member>)>,
) {
    // parameters
    let members_per_iteration = max_members_in_chunk.min(num);
    let num_iterations = num / members_per_iteration;

    let db = DbBuilder {
        members_per_chunk: max_members_in_chunk,
        num_members: num,
    }
    .build();
    // We default to a bare group unless variant wants something else.
    let variant = variant.unwrap_or(SetupVariants::Bare);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(CIPHERSUITE)
        .build();

    // // If we have a previous group/member setup, let's use it.
    // // The creator is always at 0.
    // let mut members = if let Some(members) = members {
    //     members.0.into_iter().zip(members.1).collect()
    // } else {

    // Create a new setup.
    let (creator, _) = Member::new(0);
    db.write(&creator).unwrap();
    // let creator_provider = Provider::default();
    // let creator_credential = BasicCredential::new("Creator".to_string().into());
    // let creator_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    // let creator_credential_with_key = CredentialWithKey {
    //     credential: creator_credential.into(),
    //     signature_key: creator_signer.to_public_vec().into(),
    // };

    // Create the group
    let mut creator_group = MlsGroup::new(
        &creator.provider,
        &creator.signer,
        &mls_group_create_config,
        creator.credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // vec![(
    //     creator_group,
    //     Member {
    //         provider: creator_provider,
    //         credential_with_key: creator_credential_with_key,
    //         signer: creator_signer,
    //         group_id,
    //     },
    // )]
    // };

    // Add all new members in one message
    // TODO: XXX configurable?

    println!("Inviting everyone ...");

    // We keep up to X member and groups in memory before writing them out.

    for iteration in 0..num_iterations + 1 {
        // We go one further to do the rest.
        let start = 1.max(iteration * members_per_iteration); // skip the first one (creator).
        let end = (iteration + 1) * members_per_iteration;
        let end = num.min(end); // Don't run over.

        if start == end {
            break;
        }
        println!("\n\n > Adding clients {start}..{end} ... ");

        // Members held in memory, with space for groups
        let mut new_members = vec![];
        let mut new_members_kps = vec![];

        // Generate members_per_iteration clients.
        let pb = ProgressBar::new(num as u64);
        (start..end).into_iter().for_each(|i| {
            let (member, key_package) = Member::new(i as u64);
            new_members_kps.push(key_package.key_package().clone());
            new_members.push((None::<MlsGroup>, member));
            pb.inc(1);
        });
        pb.finish();

        let welcome = {
            println!("   ... Commit ...");
            let pb = ProgressBar::new_spinner();
            pb.enable_steady_tick(Duration::from_millis(100));

            let creator_provider = &creator.provider;
            let creator_signer = &creator.signer;
            let (commit, welcome, _) = creator_group
                .add_members(creator_provider, creator_signer, &new_members_kps)
                .unwrap();

            // Merge commit on creator
            creator_group
                .merge_pending_commit(creator_provider)
                .expect("error merging pending commit");
            pb.finish();

            // Merge commit on all other members
            println!("   ... Merge commit on clients ... ");
            let start_time = std::time::Instant::now();
            let pb = ProgressBar::new(start as u64 - 1);
            (1..start).into_par_iter().for_each(|i| {
                // Read, process, write back
                let member = db.read(i as u64).unwrap();
                let mut group = member.group().unwrap();
                process_commit(&mut group, &member.provider, commit.clone());
                db.write(&member).unwrap();

                pb.inc(1);
            });
            pb.finish();
            let end_time = std::time::Instant::now();
            println!("Time: {:?}", end_time - start_time);

            welcome
        };

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected the message to be a welcome message");
        let tree = Some(creator_group.export_ratchet_tree().into());

        let pb = ProgressBar::new(members_per_iteration as u64 - 1);

        println!("   ... Join ...");
        let start_time = std::time::Instant::now();
        new_members.par_iter_mut().for_each(|(group, member)| {
            let tree = tree.clone();

            let new_group = StagedWelcome::new_from_welcome(
                &member.provider,
                mls_group_create_config.join_config(),
                welcome.clone(),
                tree.clone(),
            )
            .unwrap()
            .into_group(&member.provider)
            .unwrap();
            member.group_id = Some(new_group.group_id().clone());
            *group = Some(new_group);

            pb.inc(1);
        });
        pb.finish();
        let end_time = std::time::Instant::now();
        println!("Time: {:?}", end_time - start_time);

        // Depending on the variant we do something once everyone was added.
        match variant {
            SetupVariants::Bare => (),            // Nothing to do in this case.
            SetupVariants::CommitAfterJoin => (), // Noting to do in this case.
            SetupVariants::CommitToFullGroup => {
                println!("Commit to the full group.");
                let pb = ProgressBar::new(members_per_iteration as u64);
                // Every member commits and everyone else processes it.
                for i in 1..new_members.len() {
                    let (commit, committer_cred) = {
                        let (member_i_group, member_i) = &mut new_members[i];
                        let member_i_cred = member_i
                            .credential_with_key
                            .credential
                            .serialized_content()
                            .to_vec();
                        let commit = self_update(
                            member_i_group.as_mut().unwrap(),
                            &member_i.provider,
                            &member_i.signer,
                        );

                        (commit, member_i_cred)
                    };

                    new_members.par_iter_mut().for_each(|(group, member)| {
                        if member.credential_with_key.credential.serialized_content()
                            != committer_cred
                        {
                            process_commit(
                                group.as_mut().unwrap(),
                                &member.provider,
                                commit.clone(),
                            );
                        }
                    });
                    pb.inc(1);
                }
                pb.finish();
            }
        }

        // Store values
        println!("   ... Store ...");
        let start_time = std::time::Instant::now();
        let pb = ProgressBar::new(new_members.len() as u64);

        // Store new members
        new_members.par_iter_mut().for_each(|(_, member)| {
            db.write(member).unwrap();

            pb.inc(1);
        });

        pb.finish();
        let end_time = std::time::Instant::now();
        println!("Time: {:?}", end_time - start_time);
    }

    // Store creator
    db.write(&creator).unwrap();
}
// }

// const ITERATIONS: usize = 1000;
// const WARMUP_ITERATIONS: usize = 5;

// /// A custom benchmarking function.
// ///
// /// DO NOT USE THIS WITH LARGE INPUTS
// #[inline(always)]
// #[allow(dead_code)]
// fn bench<I, O, S, SI, R>(si: &SI, mut setup: S, mut routine: R) -> Duration
// where
//     SI: Clone,
//     S: FnMut(&SI) -> I,
//     R: FnMut(I) -> O,
// {
//     let mut time = Duration::ZERO;

//     // Warmup
//     for _ in 0..WARMUP_ITERATIONS {
//         let input = setup(si);
//         routine(input);
//     }

//     // Benchmark
//     for _ in 0..ITERATIONS {
//         let input = setup(si);

//         let start = Instant::now();
//         core::hint::black_box(routine(input));
//         let end = Instant::now();

//         time += end.duration_since(start);
//     }

//     time
// }

// // A benchmarking macro to avoid copying memory and skewing the results.
// macro_rules! bench {
//     ($groups:expr, $setup:expr, $routine:expr) => {{
//         let mut time = Duration::ZERO;

//         // Warmup
//         for _ in 0..WARMUP_ITERATIONS {
//             let input = $setup($groups);
//             $routine(input);
//         }

//         // Benchmark
//         for _ in 0..ITERATIONS {
//             let input = $setup($groups);

//             let start = Instant::now();
//             core::hint::black_box($routine(input));
//             let end = Instant::now();

//             time += end.duration_since(start);
//         }

//         time
//     }};
// }

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

    /// The max number of members in a chunk
    #[clap(short, long)]
    chunk_size: Option<usize>,
}

// mod util {
//     use std::path::Path;

//     use itertools::Itertools;

//     use super::{generate, *};

//     const MEMBERS_PATH: &str = "large-balanced-group-members.json.gzip";

//     type Members = Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>;

//     /// Read benchmark setups from the fiels previously written.
//     pub fn read(path: Option<String>) -> Vec<Vec<(MlsGroup, Member)>> {
//         let file = File::open(members_file(&path)).unwrap();
//         let mut reader = flate2::read::GzDecoder::new(file);
//         let members: Vec<Members> =
//             bincode::decode_from_std_read(&mut reader, bincode::config::standard()).unwrap();

//         let members: Vec<Vec<(MlsGroup, Member)>> = members
//             .into_iter()
//             .map(|members| {
//                 members
//                     .into_iter()
//                     .map(|m| {
//                         let m = Member::load(&m.0, &m.1, &m.2, &m.3);

//                         (m.group().unwrap(), m)
//                     })
//                     .collect()
//             })
//             .collect();

//         members
//     }

//     fn members_file(path: &Option<String>) -> std::path::PathBuf {
//         let path = path.clone().unwrap_or_default();
//         let path = Path::new(&path);
//         path.join(MEMBERS_PATH)
//     }

//     /// Generate benchmark setups and write them out.
//     pub fn write(
//         path: Option<String>,
//         group_sizes: Option<Vec<usize>>,
//         variant: Option<SetupVariants>,
//     ) {
//         let mut members = vec![];

//         let group_sizes = group_sizes.unwrap_or(generate::GROUP_SIZES.to_vec());
//         println!("Generating groups for benchmarks {group_sizes:?}...");
//         let mut smaller_groups = None;
//         for num in group_sizes.into_iter().sorted() {
//             println!("Generating group of size {num} ...");
//             // Generate and write out groups.
//             let new_groups = generate::setup(num, variant, smaller_groups);
//             let (new_groups, new_members): (Vec<MlsGroup>, Vec<Member>) =
//                 new_groups.into_iter().unzip();
//             smaller_groups = Some((new_groups.clone(), new_members.clone()));
//             let new_members: Members = new_members.into_iter().map(|m| m.serialize()).collect();
//             members.push(new_members);
//         }

//         println!("Writing out files.");
//         let file = File::create(members_file(&path)).unwrap();
//         let mut writer = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
//         bincode::encode_into_std_write(&members, &mut writer, bincode::config::standard()).unwrap();

//         println!("Wrote new test groups to file.");
//     }
// }
// use util::*;

// fn print_time(label: &str, d: Duration) {
//     let micros = d.as_micros();
//     let time = if micros < (1_000 * ITERATIONS as u128) {
//         format!("{} μs", micros / ITERATIONS as u128)
//     } else if micros < (1_000_000 * ITERATIONS as u128) {
//         format!(
//             "{:.2} ms",
//             (micros as f64 / (1_000_f64 * ITERATIONS as f64))
//         )
//     } else {
//         format!(
//             "{:.2}s",
//             (micros as f64 / (1_000_000_f64 * ITERATIONS as f64))
//         )
//     };
//     let space = if label.len() < 6 {
//         "\t\t".to_string()
//     } else {
//         "\t".to_string()
//     };

//     println!("{label}:{space}{time}");
// }

fn main() {
    let args = Args::parse();

    if args.write {
        // Only generate groups and write them out.

        pub const GROUP_SIZES: &[usize] = &[10];

        let group_sizes = args.groups.unwrap_or(GROUP_SIZES.to_vec());
        let chunk_size = args.chunk_size.unwrap_or(CHUNK_SIZE);

        let num = group_sizes[0]; // XXX: Only one
        println!("Generating groups for benchmarks {group_sizes:?}...");

        // let mut smaller_groups = None;
        // for num in group_sizes.into_iter().sorted() {
        println!("Generating group of size {num} ...");
        // Generate and write out groups.
        // let new_groups =
        setup(num, chunk_size, args.setup, None);
        // let (new_groups, new_members): (Vec<MlsGroup>, Vec<Member>) =
        //     new_groups.into_iter().unzip();
        // smaller_groups = Some((new_groups.clone(), new_members.clone()));
        // let new_members: Members = new_members.into_iter().map(|m| m.serialize()).collect();
        // members.push(new_members);
        // }

        // println!("Writing out files.");
        // let file = File::create(members_file(&path)).unwrap();
        // let mut writer = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        // bincode::encode_into_std_write(&members, &mut writer, bincode::config::standard()).unwrap();

        // println!("Wrote new test groups to file.");
        println!("Done!");

        // write(args.data, args.groups, args.setup);

        return;
    }

    // let all_groups = read(args.data);
    // for groups in all_groups.iter() {
    //     if let Some(group_sizes) = &args.groups {
    //         // Only run the groups of the sizes from the cli
    //         if !group_sizes.contains(&groups.len()) {
    //             continue;
    //         }
    //     }
    //     println!("{} Members", groups.len());

    //     // Add
    //     let time = bench!(
    //         groups,
    //         |groups: &Vec<(MlsGroup, Member)>| {
    //             let (_member_provider, _signer, _credential_with_key, key_package) =
    //                 new_member("New Member");
    //             let key_package = key_package.key_package().clone();

    //             (groups[1].clone(), key_package)
    //         },
    //         |(group1, key_package): ((MlsGroup, Member), KeyPackage)| {
    //             let (mut updater_group, updater) = group1;
    //             let provider = &updater.provider;
    //             let signer = &updater.signer;
    //             let _ = add_member(&mut updater_group, provider, signer, key_package);
    //         }
    //     );
    //     print_time("Adder", time);

    //     // Update
    //     let time = bench!(
    //         groups,
    //         |groups: &Vec<(MlsGroup, Member)>| groups[1].clone(),
    //         |group1: (MlsGroup, Member)| {
    //             // Let group 1 update and merge the commit.
    //             let (mut updater_group, updater) = group1;
    //             let provider = &updater.provider;
    //             let signer = &updater.signer;
    //             let _ = self_update(&mut updater_group, provider, signer);
    //         }
    //     );
    //     print_time("Updater", time);

    //     // Remove
    //     let time = bench!(
    //         groups,
    //         |groups: &Vec<(MlsGroup, Member)>| groups[0].clone(),
    //         |group0: (MlsGroup, Member)| {
    //             // Let group 1 update and merge the commit.
    //             let (mut updater_group, updater) = group0;
    //             let provider = &updater.provider;
    //             let signer = &updater.signer;
    //             let _ = remove_member(&mut updater_group, provider, signer);
    //         }
    //     );
    //     print_time("Remover", time);

    //     // Process an update
    //     let time = bench!(
    //         groups,
    //         |groups: &Vec<(MlsGroup, Member)>| {
    //             // Let group 1 update and merge the commit.
    //             let (updater_group, updater) = &groups[1];
    //             let provider = &updater.provider;
    //             let signer = &updater.signer;
    //             let commit = self_update(&mut updater_group.clone(), provider, signer);

    //             (groups[0].clone(), commit)
    //         },
    //         |(group0, commit): ((MlsGroup, Member), MlsMessageOut)| {
    //             // Apply the commit at member 0
    //             let (mut member_group, member) = group0;
    //             let provider = &member.provider;

    //             process_commit(&mut member_group, provider, commit);
    //         }
    //     );
    //     print_time("Process update", time);
    // }
}
