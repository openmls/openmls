use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Verifiable,
    extensions::{errors::InvalidExtensionError, *},
    group::{mls_group::tests_and_kats::utils::setup_alice_group, ExportGroupInfoError},
    messages::group_info::{GroupInfo, VerifiableGroupInfo},
    prelude::MlsMessageBodyOut,
};

/// Tests the creation of an [UnverifiedGroupInfo] and verifies it was correctly signed.
#[openmls_test::openmls_test]
fn export_group_info() {
    // Alice creates a group
    let (group_alice, _, signer, pk) = setup_alice_group(ciphersuite, provider);

    let group_info_message = group_alice
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

    let _: GroupInfo = verifiable_group_info
        .verify(provider.crypto(), &pk)
        .expect("signature verification should succeed");
}

/// Tests that extension types are validated correctly when adding to the GroupInfo.
#[openmls_test::openmls_test]
fn export_group_info_with_additional_extensions() {
    // Alice creates a group
    let (group_alice, _, signer, _pk) = setup_alice_group(ciphersuite, provider);

    // The GroupInfo can't contain these extensions
    // See https://www.rfc-editor.org/rfc/rfc9420.html#section-17.3-4
    let application_id_extension = Extension::ApplicationId(ApplicationIdExtension::new(&[]));
    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));
    let external_senders_extension = Extension::ExternalSenders(vec![]);

    let invalid_extensions = [
        application_id_extension,
        required_capabilities_extension,
        external_senders_extension,
    ];

    for extension in invalid_extensions {
        let err = group_alice
            .export_group_info_with_additional_extensions(
                provider.crypto(),
                &signer,
                true,
                Some(extension),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            ExportGroupInfoError::InvalidExtensionError(InvalidExtensionError::IllegalInGroupInfo)
        ));
    }
}
