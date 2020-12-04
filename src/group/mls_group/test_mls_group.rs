use crate::prelude::*;

#[test]
fn test_mls_group_persistence() {
    use std::fs::File;
    use std::path::Path;
    let ciphersuite = &Config::supported_ciphersuites()[0];

    // Define credential bundles
    let alice_credential_bundle =
        CredentialBundle::new("Alice".into(), CredentialType::Basic, ciphersuite.name()).unwrap();

    // Generate KeyPackages
    let alice_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new()).unwrap();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        GroupConfig::default(),
    )
    .unwrap();

    let path = Path::new("target/test_managed_group_serialization.json");
    let out_file = &mut File::create(&path).expect("Could not create file");
    alice_group
        .save(out_file)
        .expect("Could not write group state to file");

    let in_file = File::open(&path).expect("Could not open file");

    let alice_group_deserialized =
        MlsGroup::load(in_file).expect("Could not deserialize managed group");

    assert_eq!(alice_group, alice_group_deserialized);
}
