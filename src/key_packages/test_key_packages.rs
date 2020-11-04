#[cfg(test)]
use crate::config::*;
#[cfg(test)]
use crate::{extensions::*, key_packages::*};

#[test]
fn generate_key_package() {
    for &ciphersuite_name in Config::supported_ciphersuites() {
        let credential_bundle =
            CredentialBundle::new(vec![1, 2, 3], CredentialType::Basic, ciphersuite_name).unwrap();
        let kpb = KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new());
        // This is invalid because the lifetime extension is missing.
        assert!(kpb.get_key_package().verify().is_err());

        // Now with a lifetime the key package should be valid.
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite_name],
            &credential_bundle,
            vec![lifetime_extension],
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(kpb.get_key_package().verify().is_ok());

        // Now we add an invalid lifetime.
        let lifetime_extension = Box::new(LifetimeExtension::new(0));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite_name],
            &credential_bundle,
            vec![lifetime_extension],
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(kpb.get_key_package().verify().is_err());
    }
}

#[test]
fn test_codec() {
    for &ciphersuite_name in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite_name).unwrap();
        let mut kpb = KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new());

        // Encode and decode the key package.
        let enc = kpb.get_key_package().encode_detached().unwrap();

        // Decoding fails because this is not a valid key package
        let kp = KeyPackage::decode(&mut Cursor::new(&enc));
        assert_eq!(kp.err(), Some(CodecError::DecodingError));

        // Add lifetime extension to make it valid.
        let kp = kpb.get_key_package_ref_mut();
        kp.add_extension(Box::new(LifetimeExtension::new(60)));
        kp.sign(&credential_bundle);
        let enc = kpb.get_key_package().encode_detached().unwrap();

        // Now it's valid.
        let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
        assert_eq!(kpb.key_package, kp);
    }
}

#[test]
fn key_package_id_extension() {
    for &ciphersuite_name in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite_name).unwrap();
        let mut kpb = KeyPackageBundle::new(
            &[ciphersuite_name],
            &credential_bundle,
            vec![Box::new(LifetimeExtension::new(60))],
        );
        assert!(kpb.get_key_package().verify().is_ok());

        // Add an ID to the key package.
        let id = [1, 2, 3, 4];
        kpb.get_key_package_ref_mut()
            .add_extension(Box::new(KeyIDExtension::new(&id)));

        // This is invalid now.
        assert!(kpb.get_key_package().verify().is_err());

        // Sign it to make it valid.
        kpb.get_key_package_ref_mut().sign(&credential_bundle);
        assert!(kpb.get_key_package().verify().is_ok());

        // Check ID
        assert_eq!(&id[..], &kpb.get_key_package().get_id().unwrap()[..]);
    }
}
