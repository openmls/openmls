#![allow(non_snake_case)]

use rand::Rng;
use std::time::{Duration, Instant};
use std::{convert::TryFrom, fs::File};

use openmls::{node::Node, prelude::*, tree::index::NodeIndex};

type RatchetTree = Vec<Option<Node>>;
type Commit = (MlsPlaintext, Option<Welcome>, Option<KeyPackageBundle>);

#[derive(Clone)]
struct Setup {
    credential_bundles: Vec<CredentialBundle>,
    key_package_bundles: Vec<KeyPackageBundle>,
    group: Option<MlsGroup>,
    ratchet_tree: RatchetTree,
    commit: Commit,
}

fn setup_group(
    n: usize,
    ciphersuite: &Ciphersuite,
    credential_bundles: Vec<CredentialBundle>,
    mut key_package_bundles: Vec<KeyPackageBundle>,
) -> Setup {
    let group_aad = b"Group Performance Test AAD";

    // P1 creates a group
    let group_id = b"Group Performance Test";
    // Create a key package bundle for P1 and ignore the first in key_package_bundles.
    key_package_bundles.remove(0);
    let kpb =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundles[0], Vec::new()).unwrap();
    let mut group = MlsGroup::new(
        group_id,
        ciphersuite.name(),
        kpb,
        GroupConfig::default(),
        None, /* Initial PSK */
        None, /* MLS version */
    )
    .expect("Could not create group.");

    // Add all other members
    let mut add_proposals = Vec::new();
    let p1_cb = credential_bundles.get(0).unwrap();
    for i in 0..(n - 1) {
        add_proposals.push(
            group
                .create_add_proposal(
                    group_aad,
                    p1_cb,
                    key_package_bundles[i].key_package().clone(),
                )
                .expect("Could not create proposal."),
        );
    }

    let add_proposal_refs = add_proposals
        .iter()
        .map(|p| p)
        .collect::<Vec<&MlsPlaintext>>();
    let commit = match group.create_commit(
        group_aad,
        p1_cb,
        &add_proposal_refs,
        &[],
        false,
        None, /* PSK fetcher */
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    // Apply commit to p1 group
    group
        .apply_commit(
            &commit.0,
            &add_proposal_refs,
            &[],
            None, /* PSK fetcher */
        )
        .expect("error applying commit");
    let ratchet_tree = group.tree().public_key_tree_copy();

    Setup {
        credential_bundles,
        key_package_bundles,
        group: Some(group),
        ratchet_tree,
        commit,
    }
}

fn create_users(
    n: usize,
    ciphersuite: &Ciphersuite,
) -> (Vec<CredentialBundle>, Vec<KeyPackageBundle>) {
    let mut credential_bundles = Vec::new();
    let mut key_package_bundles = Vec::new();
    for i in 0..n {
        // Define credential bundles
        let cb = CredentialBundle::new(
            format!("P{}", i).into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

        // Generate KeyPackages
        let kpb = KeyPackageBundle::new(&[ciphersuite.name()], &cb, Vec::new()).unwrap();

        credential_bundles.push(cb);
        key_package_bundles.push(kpb);
    }
    (credential_bundles, key_package_bundles)
}

fn setup(n: usize, ciphersuite: &Ciphersuite) -> Setup {
    let (credential_bundles, key_package_bundles) = create_users(n, ciphersuite);
    setup_group(n, ciphersuite, credential_bundles, key_package_bundles)
}

fn join_group(mut setup: Setup, joiner: usize) {
    MlsGroup::new_from_welcome(
        setup.commit.1.unwrap(),
        Some(setup.ratchet_tree),
        setup.key_package_bundles.remove(joiner),
        None, /* PSK fetcher */
    )
    .unwrap();
}

fn join_groups(mut setup: Setup) -> (Vec<MlsGroup>, Setup) {
    // Create groups for all participants
    let mut groups = vec![setup.group.take().unwrap()];
    for kpb in setup.key_package_bundles.drain(..) {
        let group = match MlsGroup::new_from_welcome(
            setup.commit.1.clone().unwrap(),
            Some(setup.ratchet_tree.clone()),
            kpb,
            None, /* PSK fetcher */
        ) {
            Ok(group) => group,
            Err(e) => panic!("Error creating group from Welcome: {:?}", e),
        };
        groups.push(group);
    }
    (groups, setup)
}

fn send_message(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    sender: usize,
) -> (MlsCiphertext, usize, Vec<MlsGroup>, Setup) {
    let msg = format!("Hello, saying hi from {}", sender);
    let msg = groups[sender]
        .create_application_message(
            b"Msg aad",
            msg.as_bytes(),
            setup.credential_bundles.get(sender).unwrap(),
            0,
        )
        .unwrap();
    (msg, sender, groups, setup)
}

fn receive_message(
    msg: MlsCiphertext,
    receiver: usize,
    groups: &mut Vec<MlsGroup>,
) -> MlsPlaintext {
    groups[receiver].decrypt(&msg).unwrap()
}

fn send_update(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    ciphersuite: &Ciphersuite,
    sender: usize,
) -> (Vec<MlsGroup>, Setup, MlsPlaintext, MlsPlaintext) {
    let update_kpb = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &setup.credential_bundles[sender],
        vec![],
    )
    .expect("Could not create key package bundle.");

    let update_proposal = groups[sender]
        .create_update_proposal(
            b"Update proposal AAD",
            &setup.credential_bundles[sender],
            update_kpb.key_package().clone(),
        )
        .expect("Could not create proposal.");
    let (mls_plaintext_commit, _welcome_option, kpb_option) = match groups[sender].create_commit(
        &[],
        &setup.credential_bundles[sender],
        &[&update_proposal],
        &[],
        false, /* force self update */
        None,  /* PSK fetcher */
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    groups[sender]
        .apply_commit(
            &mls_plaintext_commit,
            &[&update_proposal],
            &[kpb_option.unwrap()],
            None, /* PSK fetcher */
        )
        .expect("Error applying own update commit");
    (groups, setup, mls_plaintext_commit, update_proposal)
}

fn send_updates(
    mut groups: Vec<MlsGroup>,
    mut setup: Setup,
    ciphersuite: &Ciphersuite,
) -> (Vec<MlsGroup>, Setup) {
    for i in 0..groups.len() {
        let (new_groups, new_setup, commit, proposal) = send_update(groups, setup, ciphersuite, i);
        groups = new_groups;
        setup = new_setup;
        for j in 0..groups.len() {
            if i != j {
                groups = apply_commit(groups, j, commit.clone(), proposal.clone());
            }
        }
    }
    (groups, setup)
}

fn apply_commit(
    mut groups: Vec<MlsGroup>,
    receiver: usize,
    mls_plaintext_commit: MlsPlaintext,
    proposal: MlsPlaintext,
) -> Vec<MlsGroup> {
    groups[receiver]
        .apply_commit(
            &mls_plaintext_commit,
            &[&proposal],
            &[],
            None, /* PSK fetcher */
        )
        .expect("Error applying update commit");
    groups
}

fn create_user(ciphersuite: &Ciphersuite) -> (KeyPackageBundle, CredentialBundle) {
    // Define credential bundles
    let cb = CredentialBundle::new(
        format!("PNew").into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let kpb = KeyPackageBundle::new(&[ciphersuite.name()], &cb, Vec::new()).unwrap();

    (kpb, cb)
}

fn send_add_user(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    kpb: KeyPackageBundle,
    sender: usize,
) -> (
    Commit,
    MlsPlaintext,
    Vec<MlsGroup>,
    Setup,
    usize,
    RatchetTree,
) {
    let sender_cb = setup.credential_bundles.get(sender).unwrap();
    let aad = b"Adding user";

    let add_proposal = groups[sender]
        .create_add_proposal(aad, sender_cb, kpb.key_package().clone())
        .expect("Could not create proposal.");

    let commit = groups[sender]
        .create_commit(
            aad,
            sender_cb,
            &[&add_proposal],
            &[],
            false,
            None, /* PSK fetcher */
        )
        .unwrap();

    // Apply commit to sender group
    groups[sender]
        .apply_commit(
            &commit.0,
            &[&add_proposal],
            &[],
            None, /* PSK fetcher */
        )
        .expect("error applying commit");
    let ratchet_tree = groups[sender].tree().public_key_tree_copy();
    (commit, add_proposal, groups, setup, sender, ratchet_tree)
}

fn send_remove_user(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    sender: usize,
    removed_index: usize,
) -> (
    MlsPlaintext,
    MlsPlaintext,
    Vec<MlsGroup>,
    Setup,
    usize,
    usize,
) {
    let removed_index =
        LeafIndex::try_from(NodeIndex::from(groups[removed_index].node_index())).unwrap();
    let remove_proposal = groups[sender]
        .create_remove_proposal(&[], &setup.credential_bundles[sender], removed_index)
        .expect("Could not create proposal.");
    let (commit, _welcome, kpb) = groups[sender]
        .create_commit(
            &[],
            &setup.credential_bundles[sender],
            &[&remove_proposal],
            &[],
            false, /* force self update */
            None,  /* PSK fetcher */
        )
        .unwrap();

    // Apply commit to sender group
    groups[sender]
        .apply_commit(
            &commit,
            &[&remove_proposal],
            &[kpb.unwrap()],
            None, /* PSK fetcher */
        )
        .expect("error applying commit");
    (
        commit,
        remove_proposal,
        groups,
        setup,
        sender,
        removed_index.as_usize(),
    )
}

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64 * 1e-9)
}

fn time<F, S, I, O>(name: &str, mut setup: S, mut f: F, groups: Vec<MlsGroup>, bench_setup: Setup)
where
    S: FnMut(Vec<MlsGroup>, Setup) -> I,
    F: FnMut(I) -> (Instant, Instant, O),
{
    let mut time = 0f64;
    const ITERATIONS: usize = 10;
    for _ in 0..ITERATIONS {
        let r = setup(groups.clone(), bench_setup.clone());
        let guard = pprof::ProfilerGuard::new(1000).unwrap();
        let (start, end, _o) = f(r);
        if let Ok(report) = guard.report().build() {
            let file = File::create(&format!("flamegraph_{}.svg", name.replace(" ", "_"))).unwrap();
            report.flamegraph(file).unwrap();
        };
        time += duration_nanos(end.duration_since(start));
    }
    let duration = f64::from(time / (ITERATIONS as f64));
    println!("{}: {} ns", name, duration);
}

fn bench_main(setting: BenchmarkSetting, ciphersuite: &Ciphersuite, n: usize) {
    // Basic setup for all other benchmarks.
    // The setup can be cloned in the benchmark.
    let bench_setup = setup(n, ciphersuite);
    let (groups, bench_setup) = join_groups(bench_setup);
    let (groups, bench_setup) = match setting {
        BenchmarkSetting::Bare => (groups, bench_setup),
        BenchmarkSetting::Base => send_updates(groups, bench_setup, ciphersuite),
    };

    let name = format!("{} {:?} {}", ciphersuite.name(), setting, n);

    time(
        &format!("Setup Group {}", name),
        |_groups, _bench_setup| {
            let (credential_bundles, key_package_bundles) = create_users(n, ciphersuite);
            (n, ciphersuite, credential_bundles, key_package_bundles)
        },
        |(n, ciphersuite, credential_bundles, key_package_bundles)| {
            let start = Instant::now();
            let setup = setup_group(n, ciphersuite, credential_bundles, key_package_bundles);
            (start, Instant::now(), setup)
        },
        // These two arguments aren't actually used here.
        Vec::new(),
        bench_setup.clone(),
    );

    time(
        &format!("Join Group {}", name),
        |_groups, _bench_setup| {
            let setup = setup(n, ciphersuite);
            let joiner = rand::thread_rng().gen_range(0..setup.key_package_bundles.len());
            (setup, joiner)
        },
        |(setup, joiner)| {
            let start = Instant::now();
            join_group(setup, joiner);
            (start, Instant::now(), 0)
        },
        // These two arguments aren't actually used here.
        Vec::new(),
        bench_setup.clone(),
    );

    time(
        &format!("Send Message {}", name),
        |groups, bench_setup| {
            let sender = rand::thread_rng().gen_range(0..groups.len());
            (groups, bench_setup, sender)
        },
        |(groups, setup, sender)| {
            let start = Instant::now();
            let out = send_message(groups, setup, sender);
            (start, Instant::now(), out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Receive message {}", name),
        |mut groups, bench_setup| {
            // Setup
            let sender = rand::thread_rng().gen_range(0..groups.len());
            let (msg, _sender, new_groups, _setup) =
                send_message(groups, bench_setup.clone(), sender);
            groups = new_groups;
            let mut receiver = rand::thread_rng().gen_range(0..groups.len());
            while receiver == sender {
                receiver = rand::thread_rng().gen_range(0..groups.len());
            }
            (groups.clone(), msg, receiver)
        },
        |(mut groups, msg, receiver)| {
            // Profile
            let start = Instant::now();
            let out = receive_message(msg, receiver, &mut groups);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Receive 2nd message {}", name),
        |mut groups, bench_setup| {
            // Setup
            let sender = rand::thread_rng().gen_range(0..groups.len());
            let (msg, _sender, new_groups, _setup) =
                send_message(groups, bench_setup.clone(), sender);
            groups = new_groups;
            let mut receiver = rand::thread_rng().gen_range(0..groups.len());
            while receiver == sender {
                receiver = rand::thread_rng().gen_range(0..groups.len());
            }
            receive_message(msg, receiver, &mut groups);
            let (msg, _sender, new_groups, _setup) =
                send_message(groups, bench_setup.clone(), sender);
            groups = new_groups;
            (groups.clone(), msg, receiver)
        },
        |(mut groups, msg, receiver)| {
            // Profile
            let start = Instant::now();
            let out = receive_message(msg, receiver, &mut groups);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Send Update {}", name),
        |groups, bench_setup| {
            let sender = rand::thread_rng().gen_range(0..groups.len());
            (groups, bench_setup, ciphersuite, sender)
        },
        |(groups, setup, ciphersuite, sender)| {
            let start = Instant::now();
            let out = send_update(groups, setup, ciphersuite, sender);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Receive Update {}", name),
        |groups, bench_setup| {
            let sender = rand::thread_rng().gen_range(0..groups.len());
            let (groups, _setup, commit, proposal) =
                send_update(groups, bench_setup, ciphersuite, sender);
            let mut receiver = rand::thread_rng().gen_range(0..groups.len());
            while receiver == sender {
                receiver = rand::thread_rng().gen_range(0..groups.len());
            }
            (groups, receiver, commit, proposal)
        },
        |(groups, receiver, commit, proposal)| {
            let start = Instant::now();
            let out = apply_commit(groups, receiver, commit, proposal);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Add user {}", name),
        |groups, bench_setup| {
            let (kpb, _cb) = create_user(ciphersuite);
            let sender = rand::thread_rng().gen_range(0..groups.len());
            (groups, bench_setup, kpb, sender)
        },
        |(groups, setup, kpb, sender)| {
            let start = Instant::now();
            let out = send_add_user(groups, setup, kpb, sender);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Process add user {}", name),
        |groups, bench_setup| {
            let (kpb, _cb) = create_user(ciphersuite);
            let sender = rand::thread_rng().gen_range(0..groups.len());
            let (commit, add_proposal, groups, _setup, sender, _tree) =
                send_add_user(groups, bench_setup, kpb, sender);
            let mut receiver = rand::thread_rng().gen_range(0..groups.len());
            while receiver == sender {
                receiver = rand::thread_rng().gen_range(0..groups.len());
            }
            (commit.0, add_proposal, groups, receiver)
        },
        |(commit, add_proposal, groups, receiver)| {
            let start = Instant::now();
            let out = apply_commit(groups, receiver, commit, add_proposal);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    time(
        &format!("Remove user {}", name),
        |groups, bench_setup| {
            let sender = rand::thread_rng().gen_range(0..groups.len());
            let mut removed_index = rand::thread_rng().gen_range(0..groups.len());
            while groups[removed_index].node_index() == groups[sender].node_index() {
                removed_index = rand::thread_rng().gen_range(0..groups.len());
            }
            (groups, bench_setup, sender, removed_index)
        },
        |(groups, setup, sender, removed_index)| {
            let start = Instant::now();
            let out = send_remove_user(groups, setup, sender, removed_index);
            let end = Instant::now();
            (start, end, out)
        },
        groups.clone(),
        bench_setup.clone(),
    );

    if n > 2 {
        // We don't want a self removal for n == 2 (self removal).
        time(
            &format!("Process remove user {}", name),
            |groups, bench_setup| {
                let sender = rand::thread_rng().gen_range(0..groups.len());
                let mut removed_index = rand::thread_rng().gen_range(0..groups.len());
                while groups[removed_index].node_index() == groups[sender].node_index() {
                    removed_index = rand::thread_rng().gen_range(0..groups.len());
                }
                let (commit, remove_proposal, groups, _setup, sender, removed) =
                    send_remove_user(groups, bench_setup, sender, removed_index);
                let mut receiver = rand::thread_rng().gen_range(0..groups.len());
                while receiver == sender
                    || groups[receiver].node_index() == groups[sender].node_index()
                    || groups[receiver].node_index() == (removed as u32 * 2)
                {
                    receiver = rand::thread_rng().gen_range(0..groups.len());
                }
                (commit, remove_proposal, groups, receiver)
            },
            |(commit, remove_proposal, groups, receiver)| {
                let start = Instant::now();
                let out = apply_commit(groups, receiver, commit, remove_proposal);
                let end = Instant::now();
                (start, end, out)
            },
            groups.clone(),
            bench_setup.clone(),
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum BenchmarkSetting {
    Base,
    Bare,
}

/// Usage: `cargo bench --bench group -- 2, 3, 4, 5`
fn main() {
    pretty_env_logger::init();
    let args = std::env::args().skip(1).rev().skip(1).rev();
    for n in args {
        for ciphersuite in Config::supported_ciphersuites() {
            for &setup in [BenchmarkSetting::Bare, BenchmarkSetting::Base].iter() {
                bench_main(setup, ciphersuite, n.parse::<usize>().unwrap());
            }
            break;
        }
    }
}
