#[test]
fn generate_key_package() {
    use crate::key_packages::*;

    let identity = Identity::new(
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        vec![1, 2, 3],
    );
    let kp_bundle = KeyPackageBundle::new(
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        &identity,
        None,
    );
    assert!(kp_bundle.key_package.verify());
}

#[test]
fn test_codec() {
    use crate::key_packages::*;
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let identity = Identity::new(ciphersuite, vec![1, 2, 3]);
    let kpb = KeyPackageBundle::new(ciphersuite, &identity, None);
    let enc = kpb.encode_detached().unwrap();
    let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    assert_eq!(kpb.key_package, kp);
}
