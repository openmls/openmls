use std::convert::TryFrom;

use evercrypt::prelude::get_random_vec;
use openmls::{
    group::GroupEpoch,
    messages::ConfirmationTag,
    messages::{GroupInfo, GroupSecrets},
    prelude::*,
};

#[macro_use]
mod utils;

use serde::{self, Deserialize, Serialize};
use utils::managed_utils::*;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MessagesTestVector {
    key_package: String,  // serialized KeyPackage,
    capabilities: String, // serialized Capabilities,
    lifetime: String,     // serialized {uint64 not_before; uint64 not_after;},
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

pub fn generate_test_vector(ciphersuite_name: CiphersuiteName) -> MessagesTestVector {
    let ciphersuite = Ciphersuite::new(ciphersuite_name).unwrap();
    let credential_bundle = CredentialBundle::new(
        b"OpenMLS rocks".to_vec(),
        CredentialType::Basic,
        SignatureScheme::from(ciphersuite_name),
    )
    .unwrap();
    let key_package_bundle = KeyPackageBundle::new(
        Config::supported_ciphersuite_names(),
        &credential_bundle,
        Vec::new(),
    )
    .unwrap();
    let capabilities = CapabilitiesExtension::default();
    let lifetime = LifetimeExtension::default();

    // Let's create a group to serialize some more interesting structs

    // Some basic setup functions for the managed group.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, 10, 0, callbacks);
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(
        managed_group_config,
        ManagedClientConfig::default_tests(),
        number_of_clients,
    );
    let group_id = setup.create_random_group(10, &ciphersuite).unwrap();

    let mut groups = setup.groups.borrow_mut();
    let group = groups.get_mut(&group_id).unwrap();
    let client_id = group.random_group_member();
    let clients = setup.clients.borrow();
    let client = clients.get(&client_id).unwrap().borrow();
    let ratchet_tree = client.export_ratchet_tree(&group_id).unwrap();

    // We can't easily get a "natural" GroupInfo, so we just create one here.
    let group_info = GroupInfo::new(
        group_id,
        GroupEpoch(0),
        get_random_vec(ciphersuite.hash_length()),
        get_random_vec(ciphersuite.hash_length()),
        vec![Box::new(RatchetTreeExtension::new(ratchet_tree))],
        ConfirmationTag::from(get_random_vec(ciphersuite.hash_length())),
        LeafIndex::from(0),
    );
    let group_secrets = GroupSecrets::random(ciphersuite.hash_length());
    let public_group_state = client.export_public_group_state(&group_id).unwrap();

    let key_package = client.generate_key_package(&[ciphersuite_name]).unwrap();
    let add_proposal = match client
        .propose_add_members(&group_id, &[key_package.clone()])
        .unwrap()[0]
    {
        MLSMessage::Plaintext(pt) => {}
        _ => panic!("We expected a plaintext here."),
    };
    let update_proposal = client.propose_self_update(&group_id, None).unwrap()[0];
    let remove_proposal = client.propose_remove_members(&group_id, &[2, 3]).unwrap()[0];

    let psk_id = PreSharedKeyID::new(
        PSKType::External,
        Psk::External(ExternalPsk::new(get_random_vec(ciphersuite.hash_length()))),
        get_random_vec(ciphersuite.hash_length()),
    );

    let psk_proposal = PreSharedKeyProposal { psk: psk_id };
    let reinit_proposal = ReInitProposal {
        group_id: group_id.clone(),
        version: ProtocolVersion::Mls10,
        ciphersuite: ciphersuite_name,
        extensions: vec![Box::new(RatchetTreeExtension::new(ratchet_tree))],
    };
    // We don't support external init proposals yet.
    let external_init_proposal = vec![0u8];
    // We don't support app ack proposals yet.
    let app_ack_proposal = vec![0u8];
    let (commit, welcome_option) = client.self_update(&group_id, None).unwrap();
    let welcome = welcome_option.unwrap();
    let mls_plaintext_application = client.create_message(&group_id, &[0u8]).unwrap();
}
