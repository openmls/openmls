use tls_codec::{Deserialize, Serialize};

use crate::{credentials::*, key_packages::*, messages::*, test_utils::*};

/// Tests the creation of an [UnverifiedGroupInfo] and verifies it was correctly signed.
#[apply(ciphersuites_and_backends)]
fn export_group_info(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .unwrap();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .unwrap();

    // Alice creates a group
    let group_alice: CoreGroup =
        CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
            .build(backend)
            .unwrap();

    let group_info: GroupInfo = group_alice
        .export_group_info(backend, &alice_credential_bundle, true)
        .unwrap();

    let verifiable_group_info = {
        let serialized = group_info.tls_serialize_detached().unwrap();
        VerifiableGroupInfo::tls_deserialize(&mut serialized.as_slice()).unwrap()
    };

    let _: GroupInfo = verifiable_group_info
        .verify(backend, alice_credential_bundle.credential())
        .unwrap();
}
