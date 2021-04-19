#![allow(non_snake_case)]

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand::Rng;
use std::convert::TryFrom;

use openmls::{node::Node, prelude::*, tree::index::NodeIndex};

type RatchetTree = Vec<Option<Node>>;
type Commit = (MLSPlaintext, Option<Welcome>, Option<KeyPackageBundle>);

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
        .collect::<Vec<&MLSPlaintext>>();
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
) -> (MLSCiphertext, usize, Vec<MlsGroup>, Setup) {
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

fn receive_message(msg: MLSCiphertext, receiver: usize, mut groups: Vec<MlsGroup>) {
    groups[receiver].decrypt(&msg).unwrap();
}

fn send_messages(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    sender: usize,
    num_messages: usize,
) -> (Vec<(MLSCiphertext, usize)>, Vec<MlsGroup>, Setup) {
    let mut msgs = Vec::new();
    let mut setup = setup;
    for i in 0..num_messages {
        let (msg, sender, new_groups, new_setup) = send_message(groups, setup, sender);
        msgs.push((msg, sender));
        groups = new_groups;
        setup = new_setup;
    }
    (msgs, groups, setup)
}

fn send_update(
    mut groups: Vec<MlsGroup>,
    setup: Setup,
    ciphersuite: &Ciphersuite,
    sender: usize,
) -> (Vec<MlsGroup>, Setup, MLSPlaintext, MLSPlaintext) {
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
    mls_plaintext_commit: MLSPlaintext,
    proposal: MLSPlaintext,
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
    MLSPlaintext,
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
    MLSPlaintext,
    MLSPlaintext,
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

fn send_message_bm(c: &mut Criterion, ciphersuite: &Ciphersuite, n: usize, _m: usize) {
    c.bench_function(
        &format!("Receive Message {} {}", ciphersuite.name(), n),
        |b| {
            b.iter_batched(
                || {
                    let setup = setup(n, ciphersuite);
                    let (groups, setup) = join_groups(setup);
                    let (groups, setup) = send_updates(groups, setup, ciphersuite);
                    let sender = rand::thread_rng().gen_range(0..groups.len());
                    let (msg, sender, groups, _setup) = send_message(groups, setup, sender);
                    let mut receiver = rand::thread_rng().gen_range(0..groups.len());
                    while receiver == sender {
                        receiver = rand::thread_rng().gen_range(0..groups.len());
                    }
                    (msg, groups, receiver)
                },
                |(msg, groups, receiver)| receive_message(msg, receiver, groups),
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_main(c: &mut Criterion, ciphersuite: &Ciphersuite, n: usize) {
    c.bench_function(&format!("Setup Group {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                let (credential_bundles, key_package_bundles) = create_users(n, ciphersuite);
                (n, ciphersuite, credential_bundles, key_package_bundles)
            },
            |(n, ciphersuite, credential_bundles, key_package_bundles)| {
                setup_group(n, ciphersuite, credential_bundles, key_package_bundles)
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function(&format!("Join Group {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                let setup = setup(n, ciphersuite);
                let joiner = rand::thread_rng().gen_range(0..setup.key_package_bundles.len());
                (setup, joiner)
            },
            |(setup, joiner)| join_group(setup, joiner),
            BatchSize::SmallInput,
        )
    });

    // Basic setup for all other benchmarks.
    let bench_setup = setup(n, ciphersuite);
    let (groups, bench_setup) = join_groups(bench_setup);
    let (groups, bench_setup) = send_updates(groups, bench_setup, ciphersuite);

    c.bench_function(&format!("Send Message {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                // let setup = setup(n, ciphersuite);
                // let (groups, setup) = join_groups(setup);
                // let (groups, setup) = send_updates(groups, setup, ciphersuite);
                let sender = rand::thread_rng().gen_range(0..groups.len());
                (groups, bench_setup, sender)
            },
            |(groups, setup, sender)| send_message(groups, setup, sender),
            BatchSize::SmallInput,
        )
    });

    send_message_bm(c, ciphersuite, n, 1);

    c.bench_function(&format!("Send Update {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                let setup = setup(n, ciphersuite);
                let (groups, setup) = join_groups(setup);
                let (groups, setup) = send_updates(groups, setup, ciphersuite);
                let sender = rand::thread_rng().gen_range(0..groups.len());
                (groups, setup, ciphersuite, sender)
            },
            |(groups, setup, ciphersuite, sender)| send_update(groups, setup, ciphersuite, sender),
            BatchSize::SmallInput,
        )
    });

    c.bench_function(
        &format!("Receive Update {} {}", ciphersuite.name(), n),
        |b| {
            b.iter_batched(
                || {
                    let setup = setup(n, ciphersuite);
                    let (groups, setup) = join_groups(setup);
                    let (groups, setup) = send_updates(groups, setup, ciphersuite);
                    let sender = rand::thread_rng().gen_range(0..groups.len());
                    let (groups, _setup, commit, proposal) =
                        send_update(groups, setup, ciphersuite, sender);
                    let mut receiver = rand::thread_rng().gen_range(0..groups.len());
                    while receiver == sender {
                        receiver = rand::thread_rng().gen_range(0..groups.len());
                    }
                    (groups, receiver, commit, proposal)
                },
                |(groups, receiver, commit, proposal)| {
                    apply_commit(groups, receiver, commit, proposal)
                },
                BatchSize::SmallInput,
            )
        },
    );

    c.bench_function(&format!("Add user {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                let setup = setup(n, ciphersuite);
                let (groups, setup) = join_groups(setup);
                let (groups, setup) = send_updates(groups, setup, ciphersuite);
                let (kpb, _cb) = create_user(ciphersuite);
                let sender = rand::thread_rng().gen_range(0..groups.len());
                (groups, setup, kpb, sender)
            },
            |(groups, setup, kpb, sender)| send_add_user(groups, setup, kpb, sender),
            BatchSize::SmallInput,
        )
    });

    c.bench_function(
        &format!("Process add user {} {}", ciphersuite.name(), n),
        |b| {
            b.iter_batched(
                || {
                    let setup = setup(n, ciphersuite);
                    let (groups, setup) = join_groups(setup);
                    let (groups, setup) = send_updates(groups, setup, ciphersuite);
                    let (kpb, _cb) = create_user(ciphersuite);
                    let sender = rand::thread_rng().gen_range(0..groups.len());
                    let (commit, add_proposal, groups, _setup, sender, _tree) =
                        send_add_user(groups, setup, kpb, sender);
                    let mut receiver = rand::thread_rng().gen_range(0..groups.len());
                    while receiver == sender {
                        receiver = rand::thread_rng().gen_range(0..groups.len());
                    }
                    (commit.0, add_proposal, groups, receiver)
                },
                |(commit, add_proposal, groups, receiver)| {
                    apply_commit(groups, receiver, commit, add_proposal)
                },
                BatchSize::SmallInput,
            )
        },
    );

    c.bench_function(&format!("Remove user {} {}", ciphersuite.name(), n), |b| {
        b.iter_batched(
            || {
                let setup = setup(n, ciphersuite);
                let (groups, setup) = join_groups(setup);
                let (groups, setup) = send_updates(groups, setup, ciphersuite);
                let sender = rand::thread_rng().gen_range(0..groups.len());
                let mut removed_index = rand::thread_rng().gen_range(0..groups.len());
                while groups[removed_index].node_index() == groups[sender].node_index() {
                    removed_index = rand::thread_rng().gen_range(0..groups.len());
                }
                (groups, setup, sender, removed_index)
            },
            |(groups, setup, sender, removed_index)| {
                send_remove_user(groups, setup, sender, removed_index)
            },
            BatchSize::SmallInput,
        )
    });

    if n > 2 {
        // We don't want a self removal here.
        c.bench_function(
            &format!("Process remove user {} {}", ciphersuite.name(), n),
            |b| {
                b.iter_batched(
                    || {
                        let setup = setup(n, ciphersuite);
                        let (groups, setup) = join_groups(setup);
                        let (groups, setup) = send_updates(groups, setup, ciphersuite);
                        let sender = rand::thread_rng().gen_range(0..groups.len());
                        let mut removed_index = rand::thread_rng().gen_range(0..groups.len());
                        while groups[removed_index].node_index() == groups[sender].node_index() {
                            removed_index = rand::thread_rng().gen_range(0..groups.len());
                        }
                        let (commit, remove_proposal, groups, _setup, sender, removed) =
                            send_remove_user(groups, setup, sender, removed_index);
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
                        apply_commit(groups, receiver, commit, remove_proposal)
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
}

fn benchmarks(c: &mut Criterion) {
    for ciphersuite in Config::supported_ciphersuites() {
        // for n in 2..10 {
        //     // bench_main(c, ciphersuite, n);
        //     send_message_bm(c, ciphersuite, n);
        // }
        // for n in (10..=50).step_by(10) {
        //     // bench_main(c, ciphersuite, n);
        //     send_message_bm(c, ciphersuite, n);
        // }
        for n in (100..=500).step_by(100) {
            bench_main(c, ciphersuite, n);
        }
        // for n in (1_000..10_000).step_by(1_000) {
        //     bench_main(c, ciphersuite, n);
        // }
        // for n in (10_000..=100_000).step_by(10_000) {
        //     bench_main(c, ciphersuite, n);
        // }
        // bench_main(c, ciphersuite, 10_000);
        // More than 10_000 requires too much memory.
        bench_main(c, ciphersuite, 1000);
        break;
    }
}

criterion_group!(benches, benchmarks);

criterion_main!(benches);
