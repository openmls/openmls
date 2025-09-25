use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Verifiable,
    group::mls_group::tests_and_kats::utils::setup_alice_group,
    messages::group_info::{GroupInfo, VerifiableGroupInfo},
    prelude::{ExtensionType, MlsMessageBodyOut},
};

/// Tests the creation of an [UnverifiedGroupInfo] and verifies it was correctly signed.
#[openmls_test::openmls_test]
fn export_group_info() {
    let provider = &Provider::default();
    // Alice creates a group
    let (alice_group, _, signer, pk) = setup_alice_group(ciphersuite, provider);

    let group_info_message = alice_group
        .export_group_info(provider.crypto(), &signer, true)
        .unwrap();

    let group_info = match group_info_message.body() {
        MlsMessageBodyOut::GroupInfo(group_info) => group_info,
        _ => panic!("Wrong message type"),
    };

    let verifiable_group_info = {
        let serialized = group_info.tls_serialize_detached().unwrap();
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice()).unwrap()
    };

    let group_info: GroupInfo = verifiable_group_info
        .verify(provider.crypto(), &pk)
        .expect("signature verification should succeed");

    assert!(group_info.extensions().contains(ExtensionType::ExternalPub))
}

#[openmls_test::openmls_test]
fn external_pub_in_group_info() {
    let provider = &Provider::default();
    // Alice creates a group
    let (alice_group, _, signer, _) = setup_alice_group(ciphersuite, provider);

    let group_info_message = alice_group
        .export_group_info(provider.crypto(), &signer, true)
        .unwrap();

    let group_info = match group_info_message.body() {
        MlsMessageBodyOut::GroupInfo(group_info) => group_info,
        _ => panic!("Wrong message type"),
    };

    assert!(group_info.extensions().contains(ExtensionType::ExternalPub))
}
