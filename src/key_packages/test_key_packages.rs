#[cfg(test)]
use crate::{extensions::*, key_packages::*};

#[test]
fn generate_key_package() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity =
        Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
    let credential = Credential::from(MLSCredentialType::Basic(BasicCredential::from(&identity)));
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
        Credential::from(MLSCredentialType::Basic(BasicCredential::from(&identity))),
        vec![lifetime_extension],
    );
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(kpb.get_key_package().verify());

    // Now we add an invalid lifetime.
    let lifetime_extension = Box::new(LifetimeExtension::new(0));
    let kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        Credential::from(MLSCredentialType::Basic(BasicCredential::from(&identity))),
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
    let identity = Identity::new_with_keypair(
        ciphersuite.clone(),
        vec![1, 2, 3],
        signature_keypair.clone(),
    );
    let credential = Credential::from(MLSCredentialType::Basic(BasicCredential::from(&identity)));
    let mut kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        credential,
        Vec::new(),
    );

    // Encode and decode the key package.
    let enc = kpb.get_key_package().encode_detached().unwrap();

    // Decoding fails because this is not a valid key package
    let kp = KeyPackage::decode(&mut Cursor::new(&enc));
    assert_eq!(kp.err(), Some(CodecError::DecodingError));

    // Add lifetime extension to make it valid.
    let kp = kpb.get_key_package_ref_mut();
    kp.add_extension(Box::new(LifetimeExtension::new(60)));
    kp.sign(&ciphersuite, signature_keypair.get_private_key());
    let enc = kpb.get_key_package().encode_detached().unwrap();

    // Now it's valid.
    let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    assert_eq!(kpb.key_package, kp);
}

#[test]
fn key_package_id_extension() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let identity = Identity::new_with_keypair(
        ciphersuite.clone(),
        vec![1, 2, 3],
        signature_keypair.clone(),
    );
    let credential = Credential::from(MLSCredentialType::Basic(BasicCredential::from(&identity)));
    let mut kpb = KeyPackageBundle::new(
        ciphersuite_name,
        signature_keypair.get_private_key(),
        credential,
        vec![Box::new(LifetimeExtension::new(60))],
    );
    assert!(kpb.get_key_package().verify());

    // Add an ID to the key package.
    let id = [1, 2, 3, 4];
    kpb.get_key_package_ref_mut()
        .add_extension(Box::new(KeyIDExtension::new(&id)));

    // This is invalid now.
    assert!(!kpb.get_key_package().verify());

    // Sign it to make it valid.
    kpb.get_key_package_ref_mut()
        .sign(&ciphersuite, signature_keypair.get_private_key());
    assert!(kpb.get_key_package().verify());

    // Check ID
    assert_eq!(&id[..], &kpb.get_key_package().get_id().unwrap()[..]);
}
