use crate::prelude::*;

#[test]
fn test_managed_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];
    let group_id = GroupId::from_slice(b"Test Group");

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, vec![]).unwrap();

    // Define the managed group configuration
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        HandshakeMessageFormat::Plaintext,
        update_policy,
        0,
        callbacks,
    );

    // === Alice creates a group ===
    let alice_group = ManagedGroup::new(
        &alice_credential_bundle,
        &managed_group_config,
        group_id,
        alice_key_package_bundle,
    )
    .unwrap();

    let path = Path::new("target/test_managed_group_serialization.json");
    let out_file = &mut File::create(&path).expect("Could not create file");
    alice_group
        .save(out_file)
        .expect("Could not write group state to file");

    let in_file = File::open(&path).expect("Could not open file");

    let alice_group_deserialized = ManagedGroup::load(
        in_file,
        &alice_credential_bundle,
        &ManagedGroupCallbacks::default(),
    )
    .expect("Could not deserialize managed group");

    assert_eq!(alice_group, alice_group_deserialized);
}
