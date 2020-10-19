#[cfg(test)]
use crate::{extensions::LifetimeExtension, key_packages::*};

#[test]
fn generate_key_package() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        credential,
        vec![],
    );
    // This is invalid because the lifetime extension is missing.
    assert!(!kpb.get_key_package().verify());

    // Now with a lifetime the key package should be valid.
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        Credential::Basic(BasicCredential::from(&identity)),
        vec![lifetime_extension],
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(kpb.get_key_package().verify());

    // Now we add an invalid lifetime.
    let lifetime_extension = Box::new(LifetimeExtension::new(0));
    let kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        Credential::Basic(BasicCredential::from(&identity)),
        vec![lifetime_extension],
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!kpb.get_key_package().verify());
}

#[test]
fn test_codec() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        credential,
        Vec::new(),
    );
    let _enc = kpb.encode_detached().unwrap();
    // let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    // assert_eq!(kpb.key_package, kp);
}
