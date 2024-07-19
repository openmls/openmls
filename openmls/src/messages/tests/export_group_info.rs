use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Verifiable,
    group::mls_group::tests_and_kats::utils::setup_alice_group,
    messages::group_info::{GroupInfo, VerifiableGroupInfo},
    prelude::MlsMessageBodyOut,
    test_utils::*,
};

/// Tests the creation of an [UnverifiedGroupInfo] and verifies it was correctly signed.
#[openmls_test::openmls_test]
fn export_group_info() {
    // Alice creates a group
    let (group_alice, _, signer, pk) = setup_alice_group(ciphersuite, provider);

    let group_info_message = group_alice
        .export_group_info(provider, &signer, true)
        .unwrap();

    let group_info = match group_info_message.body() {
        MlsMessageBodyOut::GroupInfo(group_info) => group_info,
        _ => panic!("Wrong message type"),
    };

    let verifiable_group_info = {
        let serialized = group_info.tls_serialize_detached().unwrap();
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice()).unwrap()
    };

    let _: GroupInfo = verifiable_group_info
        .verify(provider.crypto(), &pk)
        .expect("signature verification should succeed");
}
