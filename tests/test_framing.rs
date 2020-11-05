mod test_utils;
use test_utils::*;

use openmls::prelude::*;

#[test]
fn padding() {
    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id.clone(), CredentialType::Basic, ciphersuite.name()).unwrap();
        let kpb =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();

        let mut group_alice =
            MlsGroup::new(&id, ciphersuite.name(), kpb, GroupConfig::default()).unwrap();
        const PADDING_SIZE: usize = 10;

        for _ in 0..100 {
            let message = randombytes(random_usize() % 1000);
            let aad = randombytes(random_usize() % 1000);
            let encrypted_message = group_alice
                .create_application_message(&aad, &message, &credential_bundle)
                .ciphertext;
            let ciphertext = encrypted_message.as_slice();
            let length = ciphertext.len();
            let overflow = length % PADDING_SIZE;
            if overflow != 0 {
                panic!(
                "Error: padding overflow of {} bytes, message length: {}, padding block size: {}",
                overflow, length, PADDING_SIZE
            );
            }
        }
    }
}
