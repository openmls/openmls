use crate::extensions::LifetimeExtension;
#[cfg(test)]
use crate::key_packages::*;

#[test]
fn generate_key_package() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        credential,
        vec![lifetime_extension],
    );
    assert!(kpb.get_key_package().verify());
}

#[test]
fn test_codec() {
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
        Vec::new(),
    );
    let _enc = kpb.encode_detached().unwrap();
    // let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    // assert_eq!(kpb.key_package, kp);
}
