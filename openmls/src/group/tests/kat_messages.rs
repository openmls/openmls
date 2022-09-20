//! # Known Answer Tests for the encoding and decoding of various structs of the
//! MLS spec
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.

use crate::{
    ciphersuite::signable::Signable,
    credentials::*,
    framing::*,
    group::*,
    key_packages::*,
    messages::proposals::*,
    messages::public_group_state::*,
    messages::*,
    prelude_test::{hash_ref::KeyPackageRef, signable::Verifiable},
    schedule::psk::*,
    test_utils::*,
    tree::sender_ratchet::*,
    treesync::node::Node,
    versions::ProtocolVersion,
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, types::SignatureScheme, OpenMlsCryptoProvider};
use serde::{self, Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, TlsSliceU32, TlsVecU32};

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

pub fn generate_test_vector(ciphersuite: Ciphersuite) -> MessagesTestVector {
    let crypto = OpenMlsRustCrypto::default();
    let ciphersuite_name = ciphersuite;
    let credential_bundle = CredentialBundle::new(
        b"OpenMLS rocks".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite_name),
        &crypto,
    )
    .expect("An unexpected error occurred.");
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, &crypto, Vec::new())
            .expect("An unexpected error occurred.");
    let capabilities = CapabilitiesExtension::default();
    let lifetime = LifetimeExtension::default();

    // Let's create a group
    let mut group = CoreGroup::builder(GroupId::random(&crypto), key_package_bundle)
        .with_max_past_epoch_secrets(2)
        .build(&crypto)
        .expect("Could not create group.");

    let ratchet_tree: Vec<Option<Node>> = group.treesync().export_nodes();

    // We can't easily get a "natural" GroupInfo, so we just create one here.
    let group_info = GroupInfoPayload::new(
        group.group_id().clone(),
        0,
        crypto
            .rand()
            .random_vec(ciphersuite.hash_length())
            .expect("An unexpected error occurred."),
        crypto
            .rand()
            .random_vec(ciphersuite.hash_length())
            .expect("An unexpected error occurred."),
        &[Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::default(),
        )],
        &[Extension::RatchetTree(RatchetTreeExtension::new(
            ratchet_tree.clone(),
        ))],
        ConfirmationTag(Mac {
            mac_value: crypto
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("An unexpected error occurred.")
                .into(),
        }),
        &KeyPackageRef::from_slice(
            &crypto
                .rand()
                .random_vec(16)
                .expect("Error getting randomnes"),
        ),
    );
    let group_info = group_info
        .sign(&crypto, &credential_bundle)
        .expect("An unexpected error occurred.");
    let group_secrets =
        GroupSecrets::random_encoded(ciphersuite, &crypto, ProtocolVersion::default());
    let public_group_state = group
        .export_public_group_state(&crypto, &credential_bundle)
        .expect("An unexpected error occurred.");

    // Create a proposal to update the user's KeyPackage
    let key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, &crypto, Vec::new())
            .expect("An unexpected error occurred.");
    let key_package = key_package_bundle.key_package();
    let update_proposal = UpdateProposal {
        key_package: key_package.clone(),
    };

    // Create proposal to add a user
    let joiner_credential_bundle = CredentialBundle::new(
        b"MLS rocks".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite_name),
        &crypto,
    )
    .expect("An unexpected error occurred.");
    let joiner_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite_name],
        &joiner_credential_bundle,
        &crypto,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let add_proposal = AddProposal {
        key_package: joiner_key_package_bundle.key_package().clone(),
    };

    // Create proposal to remove a user
    // TODO #525: This is not a valid RemoveProposal since random_u32() is not a valid KeyPackageRef.
    let remove_proposal = RemoveProposal {
        removed: KeyPackageRef::from_slice(
            &crypto
                .rand()
                .random_vec(16)
                .expect("Error getting randomnes"),
        ),
    };

    let psk_id = PreSharedKeyId::new(
        ciphersuite,
        crypto.rand(),
        Psk::External(ExternalPsk::new(
            crypto
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("An unexpected error occurred."),
        )),
    )
    .expect("An unexpected error occurred.");

    let psk_proposal = PreSharedKeyProposal::new(psk_id);
    let reinit_proposal = ReInitProposal {
        group_id: group.group_id().clone(),
        version: ProtocolVersion::Mls10,
        ciphersuite: ciphersuite_name,
        extensions: vec![Extension::RatchetTree(RatchetTreeExtension::new(
            ratchet_tree.clone(),
        ))]
        .into(),
    };
    // We don't support external init proposals yet.
    let external_init_proposal = tls_codec::TlsByteVecU16::new(Vec::new());
    // We don't support app ack proposals yet.
    let app_ack_proposal = tls_codec::TlsByteVecU32::new(Vec::new());

    let framing_parameters = FramingParameters::new(b"aad", WireFormat::MlsCiphertext);

    let add_proposal_pt = group
        .create_add_proposal(
            framing_parameters,
            &credential_bundle,
            joiner_key_package_bundle.key_package().clone(),
            &crypto,
        )
        .expect("An unexpected error occurred.");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, &crypto, add_proposal_pt.clone())
            .expect("An unexpected error occurred."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&credential_bundle)
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result = group
        .create_commit(params, &crypto)
        .expect("An unexpected error occurred.");
    group
        .merge_staged_commit(create_commit_result.staged_commit, &mut proposal_store)
        .expect("Error processing staged commit.");
    let commit =
        if let MlsPlaintextContentType::Commit(commit) = create_commit_result.commit.content() {
            commit.clone()
        } else {
            panic!("Wrong content of MLS plaintext");
        };
    let welcome = create_commit_result
        .welcome_option
        .expect("An unexpected error occurred.");

    let mut receiver_group = CoreGroup::new_from_welcome(
        welcome.clone(),
        Some(group.treesync().export_nodes()),
        joiner_key_package_bundle,
        &crypto,
    )
    .expect("Error creating receiver group.");

    // Clone the secret tree to bypass FS restrictions
    let mls_ciphertext_application = group
        .create_application_message(
            b"aad",
            b"msg",
            &credential_bundle,
            random_u8() as usize,
            &crypto,
        )
        .expect("An unexpected error occurred.");
    // Replace the secret tree
    let mut verifiable_mls_plaintext_application = receiver_group
        .decrypt(
            &mls_ciphertext_application,
            &crypto,
            &SenderRatchetConfiguration::default(),
        )
        .expect("An unexpected error occurred.");
    // Sets the context implicitly.
    let credential = group
        .treesync()
        .own_leaf_node()
        .expect("An unexpected error occurred.")
        .key_package()
        .credential();
    if !verifiable_mls_plaintext_application.has_context() {
        verifiable_mls_plaintext_application.set_context(
            group
                .context()
                .tls_serialize_detached()
                .expect("Anunexpected error occured."),
        );
    }
    let mls_plaintext_application: MlsPlaintext = verifiable_mls_plaintext_application
        .verify(&crypto, credential)
        .expect("Could not verify MlsPlaintext.");

    let encryption_target = match random_u32() % 3 {
        0 => create_commit_result.commit.clone(),
        1 => add_proposal_pt.clone(),
        2 => mls_plaintext_application.clone(),
        _ => panic!("Modulo 3 of u32 shouldn't give us anything larger than 2"),
    };

    let mls_ciphertext = group
        .encrypt(encryption_target, random_u8() as usize, &crypto)
        .expect("An unexpected error occurred.");

    MessagesTestVector {
        key_package: bytes_to_hex(
            &key_package
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), // serialized KeyPackage,
        capabilities: bytes_to_hex(
            &capabilities
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), // serialized Capabilities,
        lifetime: bytes_to_hex(
            &lifetime
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), // serialized {uint64 not_before; uint64 not_after;},
        ratchet_tree: bytes_to_hex(
            &TlsSliceU32(&ratchet_tree)
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized optional<Node> ratchet_tree<1..2^32-1>; */

        group_info: bytes_to_hex(
            &group_info
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized GroupInfo */
        group_secrets: bytes_to_hex(&group_secrets.expect("An unexpected error occurred.")), /* serialized GroupSecrets */
        welcome: bytes_to_hex(
            &welcome
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized Welcome */

        public_group_state: bytes_to_hex(
            &public_group_state
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized PublicGroupState */

        add_proposal: bytes_to_hex(
            &add_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized Add */
        update_proposal: bytes_to_hex(
            &update_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized Update */
        remove_proposal: bytes_to_hex(
            &remove_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized Remove */
        pre_shared_key_proposal: bytes_to_hex(
            &psk_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized PreSharedKey */
        re_init_proposal: bytes_to_hex(
            &reinit_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized ReInit */
        external_init_proposal: bytes_to_hex(
            &external_init_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized ExternalInit */
        app_ack_proposal: bytes_to_hex(
            &app_ack_proposal
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized AppAck */

        commit: bytes_to_hex(
            &commit
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized Commit */

        mls_plaintext_application: bytes_to_hex(
            &mls_plaintext_application
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized MLSPlaintext(ApplicationData) */
        mls_plaintext_proposal: bytes_to_hex(
            &add_proposal_pt
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized MLSPlaintext(Proposal(*)) */
        mls_plaintext_commit: bytes_to_hex(
            &create_commit_result
                .commit
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized MLSPlaintext(Commit) */
        mls_ciphertext: bytes_to_hex(
            &mls_ciphertext
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
        ), /* serialized MLSCiphertext */
    }
}

#[test]
fn write_test_vectors_msg() {
    use openmls_traits::crypto::OpenMlsCrypto;
    let mut tests = Vec::new();
    const NUM_TESTS: usize = 100;

    for &ciphersuite in OpenMlsRustCrypto::default()
        .crypto()
        .supported_ciphersuites()
        .iter()
    {
        for _ in 0..NUM_TESTS {
            let test = generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_messages-new.json", &tests);
}

pub fn run_test_vector(tv: MessagesTestVector) -> Result<(), MessagesTestVectorError> {
    // KeyPackage
    let tv_key_package = hex_to_bytes(&tv.key_package);
    let mut tv_key_package_slice = tv_key_package.as_slice();
    let my_key_package = KeyPackage::tls_deserialize(&mut tv_key_package_slice)
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_key_package != my_key_package {
        log::error!("  KeyPackage encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_key_package);
        log::debug!("    Expected: {:x?}", tv_key_package);
        if cfg!(test) {
            panic!("KeyPackage encoding mismatch");
        }
        return Err(MessagesTestVectorError::KeyPackageEncodingMismatch);
    }

    // Capabilities
    log::debug!("Capabilities tv: {}", tv.capabilities);
    let tv_capabilities = hex_to_bytes(&tv.capabilities);
    let my_capabilities = CapabilitiesExtension::tls_deserialize(&mut tv_capabilities.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_capabilities != my_capabilities {
        log::error!("  Capabilities encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_capabilities);
        log::debug!("    Expected: {:x?}", tv_capabilities);
        if cfg!(test) {
            panic!("Capabilities encoding mismatch");
        }
        return Err(MessagesTestVectorError::CapabilitiesEncodingMismatch);
    }

    // Lifetime
    let tv_lifetime = hex_to_bytes(&tv.lifetime);
    let my_lifetime = LifetimeExtension::tls_deserialize(&mut tv_lifetime.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_lifetime != my_lifetime {
        log::error!("  Lifetime encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_lifetime);
        log::debug!("    Expected: {:x?}", tv_lifetime);
        if cfg!(test) {
            panic!("Lifetime encoding mismatch");
        }
        return Err(MessagesTestVectorError::LifetimeEncodingMismatch);
    }

    // RatchetTree
    log::trace!("  Serialized ratchet tree: {}", tv.ratchet_tree);
    let tv_ratchet_tree = hex_to_bytes(&tv.ratchet_tree);
    let dec_ratchet_tree =
        TlsVecU32::<Option<Node>>::tls_deserialize(&mut tv_ratchet_tree.as_slice())
            .expect("An unexpected error occurred.");
    let my_ratchet_tree = dec_ratchet_tree
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_ratchet_tree != my_ratchet_tree {
        log::error!("  RatchetTree encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_ratchet_tree);
        log::debug!("    Expected: {:x?}", tv_ratchet_tree);
        if cfg!(test) {
            panic!("RatchetTree encoding mismatch");
        }
        return Err(MessagesTestVectorError::RatchetTreeEncodingMismatch);
    }

    // GroupInfo
    let tv_group_info = hex_to_bytes(&tv.group_info);
    let my_group_info = GroupInfo::tls_deserialize(&mut tv_group_info.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_group_info != my_group_info {
        log::error!("  GroupInfo encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_group_info);
        log::debug!("    Expected: {:x?}", tv_group_info);
        if cfg!(test) {
            panic!("GroupInfo encoding mismatch");
        }
        return Err(MessagesTestVectorError::GroupInfoEncodingMismatch);
    }

    // GroupSecrets
    let tv_group_secrets = hex_to_bytes(&tv.group_secrets);
    let gs = GroupSecrets::tls_deserialize(&mut tv_group_secrets.as_slice())
        .expect("An unexpected error occurred.");
    let my_group_secrets =
        GroupSecrets::new_encoded(&gs.joiner_secret, gs.path_secret.as_ref(), &gs.psks)
            .expect("An unexpected error occurred.");
    if tv_group_secrets != my_group_secrets {
        log::error!("  GroupSecrets encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_group_secrets);
        log::debug!("    Expected: {:x?}", tv_group_secrets);
        if cfg!(test) {
            panic!("GroupSecrets encoding mismatch");
        }
        return Err(MessagesTestVectorError::GroupSecretsEncodingMismatch);
    }

    // Welcome
    let tv_welcome = hex_to_bytes(&tv.welcome);
    let my_welcome = Welcome::tls_deserialize(&mut tv_welcome.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_welcome != my_welcome {
        log::error!("  Welcome encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_welcome);
        log::debug!("    Expected: {:x?}", tv_welcome);
        if cfg!(test) {
            panic!("Welcome encoding mismatch");
        }
        return Err(MessagesTestVectorError::WelcomeEncodingMismatch);
    }

    // PublicGroupState
    let tv_public_group_state = hex_to_bytes(&tv.public_group_state);
    let my_public_group_state =
        VerifiablePublicGroupState::tls_deserialize(&mut tv_public_group_state.as_slice())
            .expect("An unexpected error occurred.")
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
    if tv_public_group_state != my_public_group_state {
        log::error!("  PublicGroupState encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_public_group_state);
        log::debug!("    Expected: {:x?}", tv_public_group_state);
        if cfg!(test) {
            panic!("PublicGroupState encoding mismatch");
        }
        return Err(MessagesTestVectorError::PublicGroupStateEncodingMismatch);
    }

    // AddProposal
    let tv_add_proposal = hex_to_bytes(&tv.add_proposal);
    let my_add_proposal = AddProposal::tls_deserialize(&mut tv_add_proposal.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_add_proposal != my_add_proposal {
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
    let tv_update_proposal = hex_to_bytes(&tv.update_proposal);
    let my_update_proposal = UpdateProposal::tls_deserialize(&mut tv_update_proposal.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_update_proposal != my_update_proposal {
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
    let tv_remove_proposal = hex_to_bytes(&tv.remove_proposal);
    let my_remove_proposal = RemoveProposal::tls_deserialize(&mut tv_remove_proposal.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_remove_proposal != my_remove_proposal {
        log::error!("  RemoveProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_remove_proposal);
        log::debug!("    Expected: {:x?}", tv_remove_proposal);
        if cfg!(test) {
            panic!("RemoveProposal encoding mismatch");
        }
        return Err(MessagesTestVectorError::RemoveProposalEncodingMismatch);
    }

    // PreSharedKeyProposal
    let tv_pre_shared_key_proposal = hex_to_bytes(&tv.pre_shared_key_proposal);
    let my_pre_shared_key_proposal =
        PreSharedKeyProposal::tls_deserialize(&mut tv_pre_shared_key_proposal.as_slice())
            .expect("An unexpected error occurred.")
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
    if tv_pre_shared_key_proposal != my_pre_shared_key_proposal {
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
    let tv_commit = hex_to_bytes(&tv.commit);
    let my_commit = Commit::tls_deserialize(&mut tv_commit.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_commit != my_commit {
        log::error!("  Commit encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_commit);
        log::debug!("    Expected: {:x?}", tv_commit);
        if cfg!(test) {
            panic!("Commit encoding mismatch");
        }
        return Err(MessagesTestVectorError::CommitEncodingMismatch);
    }

    // MlsPlaintextApplication
    let mut tv_mls_plaintext_application = hex_to_bytes(&tv.mls_plaintext_application);
    // Fake the wire format so we can deserialize
    tv_mls_plaintext_application[0] = WireFormat::MlsPlaintext as u8;
    let my_mls_plaintext_application =
        VerifiableMlsPlaintext::tls_deserialize(&mut tv_mls_plaintext_application.as_slice())
            .expect("An unexpected error occurred.")
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
    if tv_mls_plaintext_application != my_mls_plaintext_application {
        log::error!("  MlsPlaintextApplication encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_application);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_application);
        if cfg!(test) {
            panic!("MlsPlaintextApplication encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextApplicationEncodingMismatch);
    }

    // MlsPlaintext(Proposal)
    let mut tv_mls_plaintext_proposal = hex_to_bytes(&tv.mls_plaintext_proposal);
    // Fake the wire format so we can deserialize
    tv_mls_plaintext_proposal[0] = WireFormat::MlsPlaintext as u8;
    let my_mls_plaintext_proposal =
        VerifiableMlsPlaintext::tls_deserialize(&mut tv_mls_plaintext_proposal.as_slice())
            .expect("An unexpected error occurred.")
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
    if tv_mls_plaintext_proposal != my_mls_plaintext_proposal {
        log::error!("  MlsPlaintext(Proposal) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_proposal);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_proposal);
        if cfg!(test) {
            panic!("MlsPlaintext(Proposal) encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextProposalEncodingMismatch);
    }

    // MlsPlaintext(Commit)
    let mut tv_mls_plaintext_commit = hex_to_bytes(&tv.mls_plaintext_commit);
    // Fake the wire format so we can deserialize
    tv_mls_plaintext_commit[0] = WireFormat::MlsPlaintext as u8;
    let my_mls_plaintext_commit =
        VerifiableMlsPlaintext::tls_deserialize(&mut tv_mls_plaintext_commit.as_slice())
            .expect("An unexpected error occurred.")
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");
    if tv_mls_plaintext_commit != my_mls_plaintext_commit {
        log::error!("  MlsPlaintext(Commit) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_plaintext_commit);
        log::debug!("    Expected: {:x?}", tv_mls_plaintext_commit);
        if cfg!(test) {
            panic!("MlsPlaintext(Commit) encoding mismatch");
        }
        return Err(MessagesTestVectorError::MlsPlaintextCommitEncodingMismatch);
    }

    // MlsCiphertext
    let tv_mls_ciphertext = hex_to_bytes(&tv.mls_ciphertext);
    let my_mls_ciphertext = MlsCiphertext::tls_deserialize(&mut tv_mls_ciphertext.as_slice())
        .expect("An unexpected error occurred.")
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    if tv_mls_ciphertext != my_mls_ciphertext {
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
fn read_test_vectors_messages() {
    let tests: Vec<MessagesTestVector> = read("test_vectors/kat_messages.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking messages test vector.\n{:?}", e),
        }
    }
}

/// Messages test vector error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum MessagesTestVectorError {
    /// Lifetime encodings don't match.
    #[error("Lifetime encodings don't match.")]
    LifetimeEncodingMismatch,
    /// RatchetTree encodings don't match.
    #[error("RatchetTree encodings don't match.")]
    RatchetTreeEncodingMismatch,
    /// Welcome encodings don't match.
    #[error("Welcome encodings don't match.")]
    WelcomeEncodingMismatch,
    /// PublicGroupState encodings don't match.
    #[error("PublicGroupState encodings don't match.")]
    PublicGroupStateEncodingMismatch,
    /// AddProposal encodings don't match.
    #[error("AddProposal encodings don't match.")]
    AddProposalEncodingMismatch,
    /// MlsCiphertext encodings don't match.
    #[error("MlsCiphertext encodings don't match.")]
    MlsCiphertextEncodingMismatch,
    /// MlsPlaintextCommit encodings don't match.
    #[error("MlsPlaintextCommit encodings don't match.")]
    MlsPlaintextCommitEncodingMismatch,
    /// MlsPlaintextProposal encodings don't match.
    #[error("MlsPlaintextProposal encodings don't match.")]
    MlsPlaintextProposalEncodingMismatch,
    /// MlsPlaintextApplication encodings don't match.
    #[error("MlsPlaintextApplication encodings don't match.")]
    MlsPlaintextApplicationEncodingMismatch,
    /// Commit encodings don't match.
    #[error("Commit encodings don't match.")]
    CommitEncodingMismatch,
    /// PreSharedKeyProposal encodings don't match.
    #[error("PreSharedKeyProposal encodings don't match.")]
    PreSharedKeyProposalEncodingMismatch,
    /// RemoveProposal encodings don't match.
    #[error("RemoveProposal encodings don't match.")]
    RemoveProposalEncodingMismatch,
    /// UpdateProposal encodings don't match.
    #[error("UpdateProposal encodings don't match.")]
    UpdateProposalEncodingMismatch,
    /// GroupSecrets encodings don't match.
    #[error("GroupSecrets encodings don't match.")]
    GroupSecretsEncodingMismatch,
    /// GroupInfo encodings don't match.
    #[error("GroupInfo encodings don't match.")]
    GroupInfoEncodingMismatch,
    /// KeyPackage encodings don't match.
    #[error("KeyPackage encodings don't match.")]
    KeyPackageEncodingMismatch,
    /// Capabilities encodings don't match.
    #[error("Capabilities encodings don't match.")]
    CapabilitiesEncodingMismatch,
}
