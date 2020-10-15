#[cfg(test)]
use crate::{extensions::LifetimeExtension, key_packages::*};

#[test]
fn generate_key_package() {
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
        vec![],
    );
    // This is invalid because the lifetime extension is missing.
    assert!(!kpb.get_key_package().verify());

    // Now with a lifetime the key package should be valid.
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        Credential::Basic(BasicCredential::from(&identity)),
        vec![lifetime_extension],
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(kpb.get_key_package().verify());

    // Now we add an invalid lifetime.
    let lifetime_extension = Box::new(LifetimeExtension::new(0));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        Credential::Basic(BasicCredential::from(&identity)),
        vec![lifetime_extension],
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!kpb.get_key_package().verify());
}

#[test]
fn key_package_bundle_codec() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let mut kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        credential,
        Vec::new(),
    );

    // Encode and decode the key package.
    let enc = kpb.encode_detached().unwrap();

    // Decoding fails because this is not a valid key package
    let kp = KeyPackage::decode(&mut Cursor::new(&enc));
    assert_eq!(kp.err(), Some(CodecError::DecodingError));

    // Add lifetime extension to make it valid.
    let kp = kpb.get_key_package_ref_mut();
    kp.add_extension(Box::new(LifetimeExtension::new(60)));
    kp.sign(&ciphersuite, signature_keypair.get_private_key());
    let enc = kpb.encode_detached().unwrap();

    // Now it's valid.
    let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    assert_eq!(kpb.key_package, kp);
}
