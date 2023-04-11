//! # Known Answer Tests for the encoding and decoding of various structs of the
//! MLS spec
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, types::SignatureScheme, OpenMlsCryptoProvider};
use rand::{rngs::OsRng, RngCore};
use serde::{self, Deserialize, Serialize};
use thiserror::Error;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    ciphersuite::Mac,
    framing::*,
    group::{
        config::CryptoConfig,
        tests::utils::{generate_credential_bundle, generate_key_package, randombytes},
        *,
    },
    key_packages::*,
    messages::{
        proposals::*,
        proposals_in::{AddProposalIn, UpdateProposalIn},
        *,
    },
    prelude::{CredentialType, LeafNode},
    schedule::psk::*,
    test_utils::*,
    tree::sender_ratchet::*,
    treesync::node::{leaf_node::Capabilities, Node},
    versions::ProtocolVersion,
};

/// ```json
/// {
///   /* Serialized MLSMessage with MLSMessage.wire_format == mls_welcome */
///   "mls_welcome": "...",
///   /* Serialized MLSMessage with MLSMessage.wire_format == mls_group_info */
///   "mls_group_info": "...",
///   /* Serialized MLSMessage with MLSMessage.wire_format == mls_key_package */
///   "mls_key_package": "...",
///
///   /* Serialized optional<Node> ratchet_tree<1..2^32-1>; */
///   "ratchet_tree": "...",
///   /* Serialized GroupSecrets */
///   "group_secrets": "...",
///
///   "add_proposal":                      /* Serialized Add */,
///   "update_proposal":                   /* Serialized Update */,
///   "remove_proposal":                   /* Serialized Remove */,
///   "pre_shared_key_proposal":           /* Serialized PreSharedKey */,
///   "re_init_proposal":                  /* Serialized ReInit */,
///   "external_init_proposal":            /* Serialized ExternalInit */,
///   "group_context_extensions_proposal": /* Serialized GroupContextExtensions */,
///
///   "commit": /* Serialized Commit */,
///
///   /* Serialized MLSMessage with
///        MLSMessage.wire_format == mls_public_message and
///        MLSMessage.public_message.content.content_type == application */
///   "public_message_application": "...",
///   /* Serialized MLSMessage with
///        MLSMessage.wire_format == mls_public_message and
///        MLSMessage.public_message.content.content_type == proposal */
///   "public_message_proposal": "...",
///   /* Serialized MLSMessage with
///        MLSMessage.wire_format == mls_public_message and
///        MLSMessage.public_message.content.content_type == commit */
///   "public_message_commit": "...",
///   /* Serialized MLSMessage with MLSMessage.wire_format == mls_private_message */
///   "private_message": "...",
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessagesTestVector {
    #[serde(with = "hex::serde")]
    mls_welcome: Vec<u8>,
    #[serde(with = "hex::serde")]
    mls_group_info: Vec<u8>,
    #[serde(with = "hex::serde")]
    mls_key_package: Vec<u8>,

    #[serde(with = "hex::serde")]
    ratchet_tree: Vec<u8>,
    #[serde(with = "hex::serde")]
    group_secrets: Vec<u8>,

    #[serde(with = "hex::serde")]
    add_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    update_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    remove_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    pre_shared_key_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    re_init_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    external_init_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    group_context_extensions_proposal: Vec<u8>,

    #[serde(with = "hex::serde")]
    commit: Vec<u8>,

    #[serde(with = "hex::serde")]
    public_message_application: Vec<u8>,
    #[serde(with = "hex::serde")]
    public_message_proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    public_message_commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    private_message: Vec<u8>,
}

pub fn generate_test_vector(ciphersuite: Ciphersuite) -> MessagesTestVector {
    let crypto = OpenMlsRustCrypto::default();

    let alice_credential_with_key_and_signer = generate_credential_bundle(
        b"Alice".to_vec(),
        SignatureScheme::from(ciphersuite),
        &crypto,
    );

    // Create a proposal to update the user's key package.
    let alice_key_package = generate_key_package(
        ciphersuite,
        Extensions::default(),
        &crypto,
        alice_credential_with_key_and_signer.clone(),
    );

    // Let's create a group
    let mut alice_group = CoreGroup::builder(
        GroupId::random(&crypto),
        CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .with_max_past_epoch_secrets(2)
    .build(&crypto, &alice_credential_with_key_and_signer.signer)
    .unwrap();

    let alice_ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let alice_group_info = alice_group
        .export_group_info(&crypto, &alice_credential_with_key_and_signer.signer, true)
        .unwrap();

    let alice_leaf_node = {
        let capabilities = Capabilities::new(
            None,
            Some(&[
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ]),
            None,
            Some(&[ProposalType::AppAck]),
            Some(&[CredentialType::Basic]),
        );

        LeafNode::generate_update(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::Mls10,
            },
            alice_credential_with_key_and_signer
                .credential_with_key
                .clone(),
            capabilities,
            Extensions::default(),
            &crypto,
            &alice_credential_with_key_and_signer.signer.clone(),
        )
        .unwrap()
    };

    let update_proposal = UpdateProposal {
        leaf_node: alice_leaf_node,
    };

    // Bob
    let bob_credential_with_key_and_signer =
        generate_credential_bundle(b"Bob".to_vec(), SignatureScheme::from(ciphersuite), &crypto);

    let bob_key_package_bundle = KeyPackageBundle::new(
        &crypto,
        &bob_credential_with_key_and_signer.signer,
        ciphersuite,
        bob_credential_with_key_and_signer.credential_with_key,
    );

    let add_proposal = AddProposal {
        key_package: bob_key_package_bundle.key_package().clone(),
    };

    // Create proposal to remove a user
    // TODO #525: This is not a valid RemoveProposal since random_u32() is not a valid KeyPackageRef.
    let remove_proposal = RemoveProposal {
        removed: LeafNodeIndex::new(random_u32()),
    };

    let psk_proposal = {
        let psk_id = PreSharedKeyId::new(
            ciphersuite,
            crypto.rand(),
            Psk::External(ExternalPsk::new(
                crypto.rand().random_vec(ciphersuite.hash_length()).unwrap(),
            )),
        )
        .unwrap();

        PreSharedKeyProposal::new(psk_id)
    };

    let reinit_proposal = ReInitProposal {
        group_id: alice_group.group_id().clone(),
        version: ProtocolVersion::Mls10,
        ciphersuite,
        extensions: Extensions::single(Extension::RatchetTree(RatchetTreeExtension::new(
            alice_ratchet_tree.clone(),
        ))),
    };

    let external_init_proposal = ExternalInitProposal::from(randombytes(32));

    let group_context_extensions_proposal =
        GroupContextExtensionProposal::new(Extensions::default());

    let framing_parameters = FramingParameters::new(b"aad", WireFormat::PrivateMessage);

    let add_proposal_content = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package_bundle.key_package.clone(),
            &alice_credential_with_key_and_signer.signer.clone(),
        )
        .unwrap();

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content(
            ciphersuite,
            &crypto,
            add_proposal_content.clone(),
        )
        .unwrap(),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .build();
    let create_commit_result = alice_group
        .create_commit(
            params,
            &crypto,
            &alice_credential_with_key_and_signer.signer,
        )
        .unwrap();
    alice_group
        .merge_staged_commit(
            &crypto,
            create_commit_result.staged_commit,
            &mut proposal_store,
        )
        .unwrap();

    let commit = if let FramedContentBody::Commit(commit) = create_commit_result.commit.content() {
        commit.clone()
    } else {
        panic!("Wrong content of MLS plaintext");
    };

    let alice_welcome = create_commit_result.welcome_option.unwrap();

    let mut receiver_group = CoreGroup::new_from_welcome(
        alice_welcome.clone(),
        Some(alice_group.public_group().export_ratchet_tree()),
        bob_key_package_bundle,
        &crypto,
    )
    .expect("Error creating receiver group.");

    // Clone the secret tree to bypass FS restrictions
    let private_message_application = alice_group
        .create_application_message(
            b"aad",
            b"msg",
            random_u8() as usize,
            &crypto,
            &alice_credential_with_key_and_signer.signer,
        )
        .unwrap();
    // Replace the secret tree
    let verifiable_public_message_application: VerifiableAuthenticatedContentIn = receiver_group
        .decrypt(
            &private_message_application.into(),
            &crypto,
            &SenderRatchetConfiguration::default(),
        )
        .unwrap();
    let mls_content_application: AuthenticatedContent =
        AuthenticatedContentIn::from(verifiable_public_message_application).into();

    let encryption_target = match random_u32() % 3 {
        0 => create_commit_result.commit.clone(),
        1 => add_proposal_content.clone(),
        2 => mls_content_application.clone(),
        _ => panic!("Modulo 3 of u32 shouldn't give us anything larger than 2"),
    };

    let mut mac_value = vec![0u8; alice_group.ciphersuite().hash_length()];
    OsRng.fill_bytes(&mut mac_value);
    let random_membership_tag = MembershipTag(Mac {
        mac_value: mac_value.into(),
    });

    let mut application_pt: PublicMessage = mls_content_application.into();
    application_pt.set_membership_tag_test(random_membership_tag.clone());

    let mut proposal_pt: PublicMessage = add_proposal_content.into();
    proposal_pt.set_membership_tag_test(random_membership_tag.clone());

    let mut commit_pt: PublicMessage = create_commit_result.commit.into();
    commit_pt.set_membership_tag_test(random_membership_tag);

    let private_message = alice_group
        .encrypt(encryption_target, random_u8() as usize, &crypto)
        .unwrap();

    MessagesTestVector {
        mls_welcome: MlsMessageOut::from_welcome(alice_welcome, ProtocolVersion::Mls10)
            .tls_serialize_detached()
            .unwrap(),
        mls_group_info: MlsMessageOut::from(alice_group_info)
            .tls_serialize_detached()
            .unwrap(),
        mls_key_package: MlsMessageOut::from(alice_key_package)
            .tls_serialize_detached()
            .unwrap(),

        group_secrets: GroupSecrets::random_encoded(
            ciphersuite,
            &crypto,
            ProtocolVersion::default(),
        )
        .unwrap(),
        ratchet_tree: alice_ratchet_tree.tls_serialize_detached().unwrap(),

        add_proposal: add_proposal.tls_serialize_detached().unwrap(),
        update_proposal: update_proposal.tls_serialize_detached().unwrap(),
        remove_proposal: remove_proposal.tls_serialize_detached().unwrap(),
        pre_shared_key_proposal: psk_proposal.tls_serialize_detached().unwrap(),
        re_init_proposal: reinit_proposal.tls_serialize_detached().unwrap(),
        external_init_proposal: external_init_proposal.tls_serialize_detached().unwrap(),
        group_context_extensions_proposal: group_context_extensions_proposal
            .tls_serialize_detached()
            .unwrap(),

        commit: commit.tls_serialize_detached().unwrap(),

        public_message_application: MlsMessageOut::from(application_pt)
            .tls_serialize_detached()
            .unwrap(),
        public_message_proposal: MlsMessageOut::from(proposal_pt)
            .tls_serialize_detached()
            .unwrap(),
        public_message_commit: MlsMessageOut::from(commit_pt)
            .tls_serialize_detached()
            .unwrap(),
        private_message: MlsMessageOut::from_private_message(
            private_message,
            ProtocolVersion::Mls10,
        )
        .tls_serialize_detached()
        .unwrap(),
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

    write("test_vectors/messages-new.json", &tests);
}

pub fn run_test_vector(tv: MessagesTestVector) -> Result<(), EncodingMismatch> {
    // Welcome
    let tv_mls_welcome = tv.mls_welcome;
    let my_mls_welcome = MlsMessageIn::tls_deserialize_exact(&tv_mls_welcome)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_mls_welcome != my_mls_welcome {
        log::error!("  Welcome encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_welcome);
        log::debug!("    Expected: {:x?}", tv_mls_welcome);
        if cfg!(test) {
            panic!("Welcome encoding mismatch");
        }
        return Err(EncodingMismatch::Welcome);
    }

    // (Verifiable)GroupInfo
    let tv_mls_group_info = tv.mls_group_info;
    let my_mls_group_info = MlsMessageIn::tls_deserialize_exact(&tv_mls_group_info)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_mls_group_info != my_mls_group_info {
        log::error!("  VerifiableGroupInfo encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_mls_group_info);
        log::debug!("    Expected: {:x?}", tv_mls_group_info);
        if cfg!(test) {
            panic!("VerifiableGroupInfo encoding mismatch");
        }
        return Err(EncodingMismatch::GroupInfo);
    }

    // KeyPackage
    let tv_mls_key_package = tv.mls_key_package;
    let my_key_package = MlsMessageIn::tls_deserialize_exact(&tv_mls_key_package)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_mls_key_package != my_key_package {
        log::error!("  KeyPackage encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_key_package);
        log::debug!("    Expected: {:x?}", tv_mls_key_package);
        if cfg!(test) {
            panic!("KeyPackage encoding mismatch");
        }
        return Err(EncodingMismatch::KeyPackage);
    }

    // RatchetTree
    let tv_ratchet_tree = tv.ratchet_tree;
    let dec_ratchet_tree = Vec::<Option<Node>>::tls_deserialize_exact(&tv_ratchet_tree).unwrap();
    let my_ratchet_tree = dec_ratchet_tree.tls_serialize_detached().unwrap();
    if tv_ratchet_tree != my_ratchet_tree {
        log::error!("  RatchetTree encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_ratchet_tree);
        log::debug!("    Expected: {:x?}", tv_ratchet_tree);
        if cfg!(test) {
            panic!("RatchetTree encoding mismatch");
        }
        return Err(EncodingMismatch::RatchetTree);
    }

    // GroupSecrets
    let tv_group_secrets = tv.group_secrets;
    let gs = GroupSecrets::tls_deserialize_exact(&tv_group_secrets).unwrap();
    let my_group_secrets =
        GroupSecrets::new_encoded(&gs.joiner_secret, gs.path_secret.as_ref(), &gs.psks).unwrap();
    if tv_group_secrets != my_group_secrets {
        log::error!("  GroupSecrets encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_group_secrets);
        log::debug!("    Expected: {:x?}", tv_group_secrets);
        if cfg!(test) {
            panic!("GroupSecrets encoding mismatch");
        }
        return Err(EncodingMismatch::GroupSecrets);
    }

    // AddProposal
    let tv_add_proposal = tv.add_proposal;
    let my_add_proposal = AddProposalIn::tls_deserialize_exact(&tv_add_proposal)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_add_proposal != my_add_proposal {
        log::error!("  AddProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_add_proposal);
        log::debug!("    Expected: {:x?}", tv_add_proposal);
        if cfg!(test) {
            panic!("AddProposal encoding mismatch");
        }
        return Err(EncodingMismatch::AddProposal);
    }

    //update_proposal: String,         /* serialized Update */
    // UpdateProposal
    let tv_update_proposal = tv.update_proposal;
    let my_update_proposal = UpdateProposalIn::tls_deserialize_exact(&tv_update_proposal)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_update_proposal != my_update_proposal {
        log::error!("  UpdateProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_update_proposal);
        log::debug!("    Expected: {:x?}", tv_update_proposal);
        if cfg!(test) {
            panic!("UpdateProposal encoding mismatch");
        }
        return Err(EncodingMismatch::UpdateProposal);
    }
    //remove_proposal: String,         /* serialized Remove */
    // RemoveProposal
    let tv_remove_proposal = tv.remove_proposal;
    let my_remove_proposal = RemoveProposal::tls_deserialize_exact(&tv_remove_proposal)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_remove_proposal != my_remove_proposal {
        log::error!("  RemoveProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_remove_proposal);
        log::debug!("    Expected: {:x?}", tv_remove_proposal);
        if cfg!(test) {
            panic!("RemoveProposal encoding mismatch");
        }
        return Err(EncodingMismatch::RemoveProposal);
    }

    // PreSharedKeyProposal
    let tv_pre_shared_key_proposal = tv.pre_shared_key_proposal;
    let my_pre_shared_key_proposal =
        PreSharedKeyProposal::tls_deserialize_exact(&tv_pre_shared_key_proposal)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
    if tv_pre_shared_key_proposal != my_pre_shared_key_proposal {
        log::error!("  PreSharedKeyProposal encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_pre_shared_key_proposal);
        log::debug!("    Expected: {:x?}", tv_pre_shared_key_proposal);
        if cfg!(test) {
            panic!("PreSharedKeyProposal encoding mismatch");
        }
        return Err(EncodingMismatch::PreSharedKeyProposal);
    }

    // Re-Init, External Init and App-Ack Proposals go here...

    // Commit
    let tv_commit = tv.commit;
    let my_commit = CommitIn::tls_deserialize_exact(&tv_commit)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_commit != my_commit {
        log::error!("  Commit encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_commit);
        log::debug!("    Expected: {:x?}", tv_commit);
        if cfg!(test) {
            panic!("Commit encoding mismatch");
        }
        return Err(EncodingMismatch::Commit);
    }

    // MlsPlaintextApplication
    let tv_public_message_application = tv.public_message_application;
    // // Fake the wire format so we can deserialize
    //tv_public_message_application[0] = WireFormat::PublicMessage as u8;
    let my_public_message_application =
        MlsMessageIn::tls_deserialize_exact(&tv_public_message_application)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
    if tv_public_message_application != my_public_message_application {
        log::error!("  MlsPlaintextApplication encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_public_message_application);
        log::debug!("    Expected: {:x?}", tv_public_message_application);
        if cfg!(test) {
            panic!("MlsPlaintextApplication encoding mismatch");
        }
        return Err(EncodingMismatch::PublicMessageApplication);
    }

    // PublicMessage(Proposal)
    let tv_public_message_proposal = tv.public_message_proposal;
    let my_public_message_proposal =
        MlsMessageIn::tls_deserialize_exact(&tv_public_message_proposal)
            .unwrap()
            .tls_serialize_detached()
            .unwrap();
    if tv_public_message_proposal != my_public_message_proposal {
        log::error!("  PublicMessage(Proposal) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_public_message_proposal);
        log::debug!("    Expected: {:x?}", tv_public_message_proposal);
        if cfg!(test) {
            panic!("PublicMessage(Proposal) encoding mismatch");
        }
        return Err(EncodingMismatch::PublicMessageProposal);
    }

    // PublicMessage(Commit)
    let tv_public_message_commit = tv.public_message_commit;
    let my_public_message_commit = MlsMessageIn::tls_deserialize_exact(&tv_public_message_commit)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_public_message_commit != my_public_message_commit {
        log::error!("  PublicMessage(Commit) encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_public_message_commit);
        log::debug!("    Expected: {:x?}", tv_public_message_commit);
        if cfg!(test) {
            panic!("PublicMessage(Commit) encoding mismatch");
        }
        return Err(EncodingMismatch::PublicMessageCommit);
    }

    // PrivateMessage
    let tv_private_message = tv.private_message;
    let my_private_message = MlsMessageIn::tls_deserialize_exact(&tv_private_message)
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    if tv_private_message != my_private_message {
        log::error!("  PrivateMessage encoding mismatch");
        log::debug!("    Encoded: {:x?}", my_private_message);
        log::debug!("    Expected: {:x?}", tv_private_message);
        if cfg!(test) {
            panic!("PrivateMessage encoding mismatch");
        }
        return Err(EncodingMismatch::PrivateMessage);
    }

    Ok(())
}

#[test]
fn read_test_vectors_messages() {
    let tests: Vec<MessagesTestVector> = read("test_vectors/messages.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking messages test vector.\n{e:?}"),
        }
    }
}

/// Message encoding mismatch.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EncodingMismatch {
    /// RatchetTree encodings don't match.
    #[error("RatchetTree encodings don't match.")]
    RatchetTree,
    /// Welcome encodings don't match.
    #[error("Welcome encodings don't match.")]
    Welcome,
    /// AddProposal encodings don't match.
    #[error("AddProposal encodings don't match.")]
    AddProposal,
    /// PrivateMessage encodings don't match.
    #[error("PrivateMessage encodings don't match.")]
    PrivateMessage,
    /// PublicMessageCommit encodings don't match.
    #[error("PublicMessageCommit encodings don't match.")]
    PublicMessageCommit,
    /// PublicMessageProposal encodings don't match.
    #[error("PublicMessageProposal encodings don't match.")]
    PublicMessageProposal,
    /// PublicMessageApplication encodings don't match.
    #[error("PublicMessageApplication encodings don't match.")]
    PublicMessageApplication,
    /// Commit encodings don't match.
    #[error("Commit encodings don't match.")]
    Commit,
    /// PreSharedKeyProposal encodings don't match.
    #[error("PreSharedKeyProposal encodings don't match.")]
    PreSharedKeyProposal,
    /// RemoveProposal encodings don't match.
    #[error("RemoveProposal encodings don't match.")]
    RemoveProposal,
    /// UpdateProposal encodings don't match.
    #[error("UpdateProposal encodings don't match.")]
    UpdateProposal,
    /// GroupSecrets encodings don't match.
    #[error("GroupSecrets encodings don't match.")]
    GroupSecrets,
    /// GroupInfo encodings don't match.
    #[error("GroupInfo encodings don't match.")]
    GroupInfo,
    /// KeyPackage encodings don't match.
    #[error("KeyPackage encodings don't match.")]
    KeyPackage,
}
