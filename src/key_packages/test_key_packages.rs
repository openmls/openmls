#[test]
fn generate_key_package() {
    use crate::key_packages::*;
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        credential,
        None,
    );
    assert!(kpb.get_key_package().verify());
}

#[test]
fn test_codec() {
    use crate::key_packages::*;
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        credential,
        None,
    );
    let _enc = kpb.encode_detached().unwrap();
    // let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    // assert_eq!(kpb.key_package, kp);
}
