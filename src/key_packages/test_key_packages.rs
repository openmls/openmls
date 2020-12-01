#[cfg(test)]
use crate::config::*;
#[cfg(test)]
use crate::{extensions::*, key_packages::*};

#[test]
fn generate_key_package() {
    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle =
            CredentialBundle::new(vec![1, 2, 3], CredentialType::Basic, ciphersuite.name())
                .unwrap();

        // Generate a valid KeyPackage.
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension],
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(kpb.key_package().verify().is_ok());

        // Now we add an invalid lifetime.
        let lifetime_extension = Box::new(LifetimeExtension::new(0));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension],
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(kpb.key_package().verify().is_err());

        // Now with two lifetime extensions, the key package should be invalid.
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension.clone(), lifetime_extension],
        );
        assert!(kpb.is_err());
    }
}

#[test]
fn test_codec() {
    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name()).unwrap();
        let mut kpb =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();

        let kp = kpb.key_package_mut();
        kp.add_extension(Box::new(LifetimeExtension::new(60)));
        kp.sign(&credential_bundle);
        let enc = kpb.key_package().encode_detached().unwrap();

        // Now it's valid.
        let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
        assert_eq!(kpb.key_package, kp);
    }
}

#[test]
fn key_package_id_extension() {
    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name()).unwrap();
        let mut kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![Box::new(LifetimeExtension::new(60))],
        )
        .unwrap();
        assert!(kpb.key_package().verify().is_ok());

        // Add an ID to the key package.
        let id = [1, 2, 3, 4];
        kpb.key_package_mut()
            .add_extension(Box::new(KeyIDExtension::new(&id)));

        // This is invalid now.
        assert!(kpb.key_package().verify().is_err());

        // Sign it to make it valid.
        kpb.key_package_mut().sign(&credential_bundle);
        assert!(kpb.key_package().verify().is_ok());

        // Check ID
        assert_eq!(&id[..], &kpb.key_package().id().unwrap()[..]);
    }
}
