use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::{signable::Verifiable, OpenMlsSignaturePublicKey},
    extensions::{errors::InvalidExtensionError, *},
    group::{
        mls_group::tests_and_kats::utils::{setup_alice_bob_group, setup_alice_group},
        ExportGroupInfoError,
    },
    messages::group_info::{GroupInfo, VerifiableGroupInfo},
    prelude::{ExtensionType, ExtensionTypeNotValidInGroupInfoError, MlsMessageBodyOut},
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

/// A writer that accepts at most one byte per `write` call, as
/// `std::io::Write` allows.
struct OneByteWriter(Vec<u8>);

impl std::io::Write for OneByteWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(byte) = buf.first() else {
            return Ok(0);
        };
        self.0.push(*byte);
        Ok(1)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A signed group info serializes completely into a writer that writes
/// partially, and equals the group info obtained by decoding and verifying it.
#[openmls_test::openmls_test]
fn signed_group_info_serialization_and_equality() {
    let provider = &Provider::default();
    let (alice_group, _, signer, pk) = setup_alice_group(ciphersuite, provider);

    let group_info_message = alice_group
        .export_group_info(provider.crypto(), &signer, true)
        .unwrap();
    let MlsMessageBodyOut::GroupInfo(group_info) = group_info_message.body() else {
        panic!("Wrong message type")
    };

    let serialized = group_info.tls_serialize_detached().unwrap();
    let mut writer = OneByteWriter(Vec::new());
    let written = group_info.tls_serialize(&mut writer).unwrap();
    assert_eq!(writer.0, serialized);
    assert_eq!(written, serialized.len());

    let verified_group_info: GroupInfo =
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice())
            .unwrap()
            .verify(provider.crypto(), &pk)
            .unwrap();
    assert_eq!(&verified_group_info, group_info);
}

#[openmls_test::openmls_test]
fn group_info_signer_is_exporting_member() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (_alice_group, _, bob_group, bob_signer, _, _) =
        setup_alice_bob_group(ciphersuite, alice_provider, bob_provider);
    let bob_leaf_index = bob_group.own_leaf_index();

    let verifiable_group_info = bob_group
        .export_group_info(bob_provider.crypto(), &bob_signer, true)
        .unwrap()
        .into_verifiable_group_info()
        .unwrap();
    assert_eq!(verifiable_group_info.signer(), bob_leaf_index);

    let bob_pk = OpenMlsSignaturePublicKey::new(
        bob_signer.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();
    let group_info: GroupInfo = verifiable_group_info
        .verify(bob_provider.crypto(), &bob_pk)
        .expect("signature verification should succeed");
    assert_eq!(group_info.signer(), bob_leaf_index);
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

/// Tests that extension types are validated correctly when adding to the GroupInfo.
#[openmls_test::openmls_test]
fn export_group_info_with_additional_extensions() {
    let provider = &Provider::default();
    // Alice creates a group
    let (group_alice, _, signer, _pk) = setup_alice_group(ciphersuite, provider);

    // The GroupInfo can't contain these extensions
    // See https://www.rfc-editor.org/rfc/rfc9420.html#section-17.3-4
    let application_id_extension = Extension::ApplicationId(ApplicationIdExtension::new(&[]));
    let required_capabilities_extension =
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(&[], &[], &[]));
    let external_senders_extension = Extension::ExternalSenders(vec![]);

    let invalid_extensions = [
        (
            application_id_extension,
            ExtensionTypeNotValidInGroupInfoError(ExtensionType::ApplicationId),
        ),
        (
            required_capabilities_extension,
            ExtensionTypeNotValidInGroupInfoError(ExtensionType::RequiredCapabilities),
        ),
        (
            external_senders_extension,
            ExtensionTypeNotValidInGroupInfoError(ExtensionType::ExternalSenders),
        ),
    ];

    for (extension, _t) in invalid_extensions {
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
            ExportGroupInfoError::InvalidExtensionError(
                InvalidExtensionError::ExtensionTypeNotValidInGroupInfo(_t)
            )
        ));
    }
}
