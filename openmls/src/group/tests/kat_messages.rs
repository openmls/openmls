//! # Known Answer Tests for the encoding and decoding of various structs of the
//! MLS spec
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.

use crate::{
    ciphersuite::signable::Signable,
    group::GroupEpoch,
    messages::{Commit, GroupInfo, GroupSecrets, PublicGroupState},
    messages::{ConfirmationTag, GroupInfoPayload},
    node::Node,
    prelude::*,
    test_util::*,
    utils::*,
};
use evercrypt::prelude::random_vec;

use serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessagesTestVector {
    key_package: String,  /* serialized KeyPackage, */
    capabilities: String, /* serialized Capabilities, */
    lifetime: String,     /* serialized {uint64 not_before; uint64 not_after;}, */
    ratchet_tree: String, /* serialized optional<Node> ratchet_tree<1..2^32-1>; */

    group_info: String,    /* serialized GroupInfo */
    group_secrets: String, /* serialized GroupSecrets */
    welcome: String,       /* serialized Welcome */

    public_group_state: String, /* serialized PublicGroupState */

    add_proposal: String,            /* serialized Add */
    update_proposal: String,         /* serialized Update */
    remove_proposal: String,         /* serialized Remove */
    pre_shared_key_proposal: String, /* serialized PreSharedKey */
    re_init_proposal: String,        /* serialized ReInit */
    external_init_proposal: String,  /* serialized ExternalInit */
    app_ack_proposal: String,        /* serialized AppAck */

    commit: String, /* serialized Commit */

    mls_plaintext_application: String, /* serialized MLSPlaintext(ApplicationData) */
    mls_plaintext_proposal: String,    /* serialized MLSPlaintext(Proposal(*)) */
    mls_plaintext_commit: String,      /* serialized MLSPlaintext(Commit) */
    mls_ciphertext: String,            /* serialized MLSCiphertext */
}

pub fn generate_test_vector(ciphersuite: &'static Ciphersuite) -> MessagesTestVector {
    let ciphersuite_name = ciphersuite.name();
    let credential_bundle = CredentialBundle::new(
        b"OpenMLS rocks".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite_name),
    )
    .unwrap();
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap();
    let capabilities = CapabilitiesExtension::default();
    let lifetime = LifetimeExtension::default();

    // Let's create a group
    let group_id = GroupId::random();
    let config = GroupConfig::default();
    let mut group = MlsGroup::new(
        &group_id.as_slice(),
        ciphersuite_name,
        key_package_bundle,
        config,
        None,
        ProtocolVersion::default(),
    )
    .unwrap();

    let ratchet_tree = group.tree().public_key_tree_copy();

    // We can't easily get a "natural" GroupInfo, so we just create one here.
    let group_info = GroupInfoPayload::new(
        group_id.clone(),
        GroupEpoch(0),
        random_vec(ciphersuite.hash_length()),
        random_vec(ciphersuite.hash_length()),
        vec![Box::new(RatchetTreeExtension::new(ratchet_tree.clone()))],
        ConfirmationTag(Mac {
            mac_value: random_vec(ciphersuite.hash_length()),
        }),
        LeafIndex::from(random_u32()),
    );
    let group_info = group_info.sign(&&credential_bundle).unwrap();
    let group_secrets = GroupSecrets::random_encoded(ciphersuite, ProtocolVersion::default());
    let public_group_state = group.export_public_group_state(&credential_bundle).unwrap();

    // Create some proposals
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap();
    let key_package = key_package_bundle.key_package();

    let add_proposal = AddProposal {
        key_package: key_package.clone(),
    };
    let update_proposal = UpdateProposal {
        key_package: key_package.clone(),
    };
    let remove_proposal = RemoveProposal {
        removed: random_u32(),
    };

    let psk_id = PreSharedKeyId::new(
        PskType::External,
        Psk::External(ExternalPsk::new(random_vec(ciphersuite.hash_length()))),
        random_vec(ciphersuite.hash_length()),
    );

    let psk_proposal = PreSharedKeyProposal { psk: psk_id };
    let reinit_proposal = ReInitProposal {
        group_id,
        version: ProtocolVersion::Mls10,
        ciphersuite: ciphersuite_name,
        extensions: vec![Box::new(RatchetTreeExtension::new(ratchet_tree.clone()))],
    };
    // We don't support external init proposals yet.
    let external_init_proposal: Vec<u8> = vec![];
    // We don't support app ack proposals yet.
    let app_ack_proposal: Vec<u8> = vec![];
    let joiner_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap();

    let add_proposal_pt = group
        .create_add_proposal(
            b"aad",
            &credential_bundle,
            joiner_key_package_bundle.key_package().clone(),
        )
        .unwrap();
    let (commit_pt, welcome_option, _option_kpb) = group
        .create_commit(
            b"aad",
            &credential_bundle,
            &[&add_proposal_pt],
            &[],
            true,
            None,
        )
        .unwrap();
    let commit = if let MlsPlaintextContentType::Commit(commit) = commit_pt.content() {
        commit.clone()
    } else {
        panic!("Wrong content of MLS plaintext");
    };
    let welcome = welcome_option.unwrap();
    let mls_ciphertext_application = group
        .create_application_message(b"aad", b"msg", &credential_bundle, random_u8() as usize)
        .unwrap();
    let mls_plaintext_application = group.decrypt(&mls_ciphertext_application).unwrap();

    let encryption_target = match random_u32() % 3 {
        0 => commit_pt.clone(),
        1 => add_proposal_pt.clone(),
        2 => mls_plaintext_application.clone(),
        _ => panic!("Modulo 3 of u32 shouldn't give us anything larger than 2"),
    };

    let mls_ciphertext = group
        .encrypt(encryption_target, random_u8() as usize)
        .unwrap();

    MessagesTestVector {
        key_package: bytes_to_hex(&key_package.encode_detached().unwrap()), // serialized KeyPackage,
        capabilities: bytes_to_hex(&capabilities.encode_detached().unwrap()), // serialized Capabilities,
        lifetime: bytes_to_hex(&lifetime.encode_detached().unwrap()), // serialized {uint64 not_before; uint64 not_after;},
        ratchet_tree: bytes_to_hex(&ratchet_tree.encode_detached().unwrap()), /* serialized optional<Node> ratchet_tree<1..2^32-1>; */

        group_info: bytes_to_hex(&group_info.encode_detached().unwrap()), /* serialized GroupInfo */
        group_secrets: bytes_to_hex(&group_secrets.unwrap()), /* serialized GroupSecrets */
        welcome: bytes_to_hex(&welcome.encode_detached().unwrap()), /* serialized Welcome */

        public_group_state: bytes_to_hex(&public_group_state.encode_detached().unwrap()), /* serialized PublicGroupState */

        add_proposal: bytes_to_hex(&add_proposal.encode_detached().unwrap()), /* serialized Add */
        update_proposal: bytes_to_hex(&update_proposal.encode_detached().unwrap()), /* serialized Update */
        remove_proposal: bytes_to_hex(&remove_proposal.encode_detached().unwrap()), /* serialized Remove */
        pre_shared_key_proposal: bytes_to_hex(&psk_proposal.encode_detached().unwrap()), /* serialized PreSharedKey */
        re_init_proposal: bytes_to_hex(&reinit_proposal.encode_detached().unwrap()), /* serialized ReInit */
        external_init_proposal: bytes_to_hex(&external_init_proposal.encode_detached().unwrap()), /* serialized ExternalInit */
        app_ack_proposal: bytes_to_hex(&app_ack_proposal.encode_detached().unwrap()), /* serialized AppAck */

        commit: bytes_to_hex(&commit.encode_detached().unwrap()), /* serialized Commit */

        mls_plaintext_application: bytes_to_hex(
            &mls_plaintext_application.encode_detached().unwrap(),
        ), /* serialized MLSPlaintext(ApplicationData) */
        mls_plaintext_proposal: bytes_to_hex(&add_proposal_pt.encode_detached().unwrap()), /* serialized MLSPlaintext(Proposal(*)) */
        mls_plaintext_commit: bytes_to_hex(&commit_pt.encode_detached().unwrap()), /* serialized MLSPlaintext(Commit) */
        mls_ciphertext: bytes_to_hex(&mls_ciphertext.encode_detached().unwrap()), /* serialized MLSCiphertext */
    }
}

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for ciphersuite in Config::supported_ciphersuites() {
        for _ in 0..NUM_TESTS {
            let test = generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_messages-new.json", &tests);
}

pub fn run_test_vector(tv: MessagesTestVector) -> Result<(), MessagesTestVectorError> {
    // KeyPackage
    let tv_key_package = &hex_to_bytes(&tv.key_package);
    let my_key_package = KeyPackage::decode_detached(&tv_key_package)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_key_package != &my_key_package {
        log::error!("  KeyPackage encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_key_package);
        log::debug!("    Expected: {:x?}", tv_key_package);
        if cfg!(test) {
            panic!("KeyPackage encoding mismatch");
        }
        return Err(MessagesTestVectorError::KeyPackageEncodingMismatch);
    }

    // Capabilities
    let tv_capabilities = &hex_to_bytes(&tv.capabilities);
    let my_capabilities = CapabilitiesExtension::decode_detached(&tv_capabilities)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_capabilities != &my_capabilities {
        log::error!("  Capabilities encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_capabilities);
        log::debug!("    Expected: {:x?}", tv_capabilities);
        if cfg!(test) {
            panic!("Capabilities encoding mismatch");
        }
        return Err(MessagesTestVectorError::CapabilitiesEncodingMismatch);
    }

    // Lifetime
    let tv_lifetime = &hex_to_bytes(&tv.lifetime);
    let my_lifetime = LifetimeExtension::decode_detached(&tv_lifetime)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_lifetime != &my_lifetime {
        log::error!("  Lifetime encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_lifetime);
        log::debug!("    Expected: {:x?}", tv_lifetime);
        if cfg!(test) {
            panic!("Lifetime encoding mismatch");
        }
        return Err(MessagesTestVectorError::LifetimeEncodingMismatch);
    }

    // RatchetTree
    let tv_ratchet_tree = &hex_to_bytes(&tv.ratchet_tree);
    let mut cursor = Cursor::new(tv_ratchet_tree);
    let dec_ratchet_tree: Vec<Option<Node>> = decode_vec(VecSize::VecU32, &mut cursor).unwrap();
    let my_ratchet_tree = dec_ratchet_tree.encode_detached().unwrap();
    if tv_ratchet_tree != &my_ratchet_tree {
        log::error!("  RatchetTree encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_ratchet_tree);
        log::debug!("    Expected: {:x?}", tv_ratchet_tree);
        if cfg!(test) {
            panic!("RatchetTree encoding mismatch");
        }
        return Err(MessagesTestVectorError::RatchetTreeEncodingMismatch);
    }

    // GroupInfo
    let tv_group_info = &hex_to_bytes(&tv.group_info);
    let my_group_info = GroupInfo::decode_detached(&tv_group_info)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_group_info != &my_group_info {
        log::error!("  GroupInfo encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_group_info);
        log::debug!("    Expected: {:x?}", tv_group_info);
        if cfg!(test) {
            panic!("GroupInfo encoding mismatch");
        }
        return Err(MessagesTestVectorError::GroupInfoEncodingMismatch);
    }

    // GroupSecrets
    let tv_group_secrets = &hex_to_bytes(&tv.group_secrets);
    let gs = GroupSecrets::decode_detached(&tv_group_secrets).unwrap();
    let my_group_secrets =
        GroupSecrets::new_encoded(&gs.joiner_secret, gs.path_secret.as_ref(), gs.psks.as_ref())
            .unwrap();
    if tv_group_secrets != &my_group_secrets {
        log::error!("  GroupSecrets encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_group_secrets);
        log::debug!("    Expected: {:x?}", tv_group_secrets);
        if cfg!(test) {
            panic!("GroupSecrets encoding mismatch");
        }
        return Err(MessagesTestVectorError::GroupSecretsEncodingMismatch);
    }

    // Welcome
    let tv_welcome = &hex_to_bytes(&tv.welcome);
    let my_welcome = Welcome::decode_detached(&tv_welcome)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_welcome != &my_welcome {
        log::error!("  Welcome encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_welcome);
        log::debug!("    Expected: {:x?}", tv_welcome);
        if cfg!(test) {
            panic!("Welcome encoding mismatch");
        }
        return Err(MessagesTestVectorError::WelcomeEncodingMismatch);
    }

    // PublicGroupState
    let tv_public_group_state = &hex_to_bytes(&tv.public_group_state);
    let my_public_group_state = PublicGroupState::decode_detached(&tv_public_group_state)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_public_group_state != &my_public_group_state {
        log::error!("  PublicGroupState encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_public_group_state);
        log::debug!("    Expected: {:x?}", tv_public_group_state);
        if cfg!(test) {
            panic!("PublicGroupState encoding mismatch");
        }
        return Err(MessagesTestVectorError::PublicGroupStateEncodingMismatch);
    }

    // AddProposal
    let tv_add_proposal = &hex_to_bytes(&tv.add_proposal);
    let my_add_proposal = AddProposal::decode_detached(&tv_add_proposal)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_add_proposal != &my_add_proposal {
        log::error!("  AddProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_add_proposal);
        log::debug!("    Expected: {:x?}", tv_add_proposal);
        if cfg!(test) {
            panic!("AddProposal encoding mismatch");
        }
        return Err(MessagesTestVectorError::AddProposalEncodingMismatch);
    }

    //update_proposal: String,         /* serialized Update */
    // UpdateProposal
    let tv_update_proposal = &hex_to_bytes(&tv.update_proposal);
    let my_update_proposal = UpdateProposal::decode_detached(&tv_update_proposal)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_update_proposal != &my_update_proposal {
        log::error!("  UpdateProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_update_proposal);
        log::debug!("    Expected: {:x?}", tv_update_proposal);
        if cfg!(test) {
            panic!("UpdateProposal encoding mismatch");
        }
        return Err(MessagesTestVectorError::UpdateProposalEncodingMismatch);
    }
    //remove_proposal: String,         /* serialized Remove */
    // RemoveProposal
    let tv_remove_proposal = &hex_to_bytes(&tv.remove_proposal);
    let my_remove_proposal = RemoveProposal::decode_detached(&tv_remove_proposal)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_remove_proposal != &my_remove_proposal {
        log::error!("  RemoveProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_remove_proposal);
        log::debug!("    Expected: {:x?}", tv_remove_proposal);
        if cfg!(test) {
            panic!("RemoveProposal encoding mismatch");
        }
        return Err(MessagesTestVectorError::RemoveProposalEncodingMismatch);
    }

    // PreSharedKeyProposal
    let tv_pre_shared_key_proposal = &hex_to_bytes(&tv.pre_shared_key_proposal);
    let my_pre_shared_key_proposal =
        PreSharedKeyProposal::decode_detached(&tv_pre_shared_key_proposal)
            .unwrap()
            .encode_detached()
            .unwrap();
    if tv_pre_shared_key_proposal != &my_pre_shared_key_proposal {
        log::error!("  PreSharedKeyProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_pre_shared_key_proposal);
        log::debug!("    Expected: {:x?}", tv_pre_shared_key_proposal);
        if cfg!(test) {
            panic!("PreSharedKeyProposal encoding mismatch");
        }
        return Err(MessagesTestVectorError::PreSharedKeyProposalEncodingMismatch);
    }

    // Re-Init, External Init and App-Ack Proposals go here...

    // Commit
    let tv_commit = &hex_to_bytes(&tv.commit);
    let my_commit = Commit::decode_detached(&tv_commit)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_commit != &my_commit {
        log::error!("  Commit encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_commit);
        log::debug!("    Expected: {:x?}", tv_commit);
        if cfg!(test) {
            panic!("Commit encoding mismatch");
        }
        return Err(MessagesTestVectorError::CommitEncodingMismatch);
    }

    // MlsPlaintextApplication
    let tv_mls_plaintext_application = &hex_to_bytes(&tv.mls_plaintext_application);
    let my_mls_plaintext_application =
        VerifiableMlsPlaintext::decode_detached(&tv_mls_plaintext_application)
            .unwrap()
            .encode_detached()
            .unwrap();
    if tv_mls_plaintext_application != &my_mls_plaintext_application {
        log::error!("  MlsPlaintextApplication encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_application);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_application);
        if cfg!(test) {
            panic!("MlsPlaintextApplication encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextApplicationEncodingMismatch);
    }

    // MlsPlaintext(Proposal)
    let tv_mls_plaintext_proposal = &hex_to_bytes(&tv.mls_plaintext_proposal);
    let my_mls_plaintext_proposal =
        VerifiableMlsPlaintext::decode_detached(&tv_mls_plaintext_proposal)
            .unwrap()
            .encode_detached()
            .unwrap();
    if tv_mls_plaintext_proposal != &my_mls_plaintext_proposal {
        log::error!("  MlsPlaintext(Proposal) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_proposal);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_proposal);
        if cfg!(test) {
            panic!("MlsPlaintext(Proposal) encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextProposalEncodingMismatch);
    }

    // MlsPlaintext(Commit)
    let tv_mls_plaintext_commit = &hex_to_bytes(&tv.mls_plaintext_commit);
    let my_mls_plaintext_commit = VerifiableMlsPlaintext::decode_detached(&tv_mls_plaintext_commit)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_mls_plaintext_commit != &my_mls_plaintext_commit {
        log::error!("  MlsPlaintext(Commit) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_commit);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_commit);
        if cfg!(test) {
            panic!("MlsPlaintext(Commit) encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextCommitEncodingMismatch);
    }

    // MlsCiphertext
    let tv_mls_ciphertext = &hex_to_bytes(&tv.mls_ciphertext);
    let my_mls_ciphertext = MlsCiphertext::decode_detached(&tv_mls_ciphertext)
        .unwrap()
        .encode_detached()
        .unwrap();
    if tv_mls_ciphertext != &my_mls_ciphertext {
        log::error!("  MlsCiphertext encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_ciphertext);
        log::debug!("    Expected: {:x?}", tv_mls_ciphertext);
        if cfg!(test) {
            panic!("MlsCiphertext encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsCiphertextEncodingMismatch);
    }
    Ok(())
}

#[test]
fn read_test_vectors() {
    let tests: Vec<MessagesTestVector> = read("test_vectors/kat_messages.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking messages test vector.\n{:?}", e),
        }
    }
}

implement_error! {
    pub enum MessagesTestVectorError {
        LifetimeEncodingMismatch = "Lifetime encodings don't match.",
        RatchetTreeEncodingMismatch = "RatchetTree encodings don't match.",
        WelcomeEncodingMismatch = "Welcome encodings don't match.",
        PublicGroupStateEncodingMismatch = "PublicGroupState encodings don't match.",
        AddProposalEncodingMismatch = "AddProposal encodings don't match.",
        MlsCiphertextEncodingMismatch = "MlsCiphertext encodings don't match.",
        MlsPlaintextCommitEncodingMismatch = "MlsPlaintextCommit encodings don't match.",
        MlsPlaintextProposalEncodingMismatch = "MlsPlaintextProposal encodings don't match.",
        MlsPlaintextApplicationEncodingMismatch = "MlsPlaintextApplication encodings don't match.",
        CommitEncodingMismatch = "Commit encodings don't match.",
        PreSharedKeyProposalEncodingMismatch = "PreSharedKeyProposal encodings don't match.",
        RemoveProposalEncodingMismatch = "RemoveProposal encodings don't match.",
        UpdateProposalEncodingMismatch = "UpdateProposal encodings don't match.",
        GroupSecretsEncodingMismatch = "GroupSecrets encodings don't match.",
        GroupInfoEncodingMismatch = "GroupInfo encodings don't match.",
        KeyPackageEncodingMismatch = "KeyPackage encodings don't match.",
        CapabilitiesEncodingMismatch = "Capabilities encodings don't match.",
    }
}
