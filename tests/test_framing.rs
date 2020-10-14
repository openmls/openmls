mod test_utils;
use test_utils::*;

use maelstrom::ciphersuite::*;
use maelstrom::creds::*;
use maelstrom::group::*;
use maelstrom::key_packages::*;

#[test]
fn padding() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(ciphersuite_name);
    let id = vec![1, 2, 3];
    let identity = Identity::new(ciphersuite, vec![1, 2, 3]);
    let signature_keypair = ciphersuite.new_signature_keypair();
    let credential = Credential::Basic(BasicCredential::from(&identity));
    let kpb = KeyPackageBundle::new(
        &ciphersuite,
        signature_keypair.get_private_key(),
        credential,
        Vec::new(),
    );

    let mut group_alice = MlsGroup::new(&id, ciphersuite, kpb);
    const PADDING_SIZE: usize = 10;

    for _ in 0..100 {
        let message = randombytes(random_usize() % 1000);
        let aad = randombytes(random_usize() % 1000);
        let mls_plaintext = group_alice.create_application_message(
            &aad,
            &message,
            signature_keypair.get_private_key(),
        );
        let encrypted_message = group_alice.encrypt(mls_plaintext).as_slice();
        let length = encrypted_message.len();
        let overflow = length % PADDING_SIZE;
        if overflow != 0 {
            panic!(
                "Error: padding overflow of {} bytes, message length: {}, padding block size: {}",
                overflow, length, PADDING_SIZE
            );
        }
    }
}
