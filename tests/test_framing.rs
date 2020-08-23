mod test_utils;
use test_utils::*;

use maelstrom::ciphersuite::*;
use maelstrom::client::*;
use maelstrom::group::*;

#[test]
fn padding() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let client = Client::new(vec![1, 2, 3], vec![ciphersuite_name]);
    let mut group_alice = MlsGroup::new(client, &[1, 2, 3], ciphersuite_name);
    const PADDING_SIZE: usize = 10;

    for _ in 0..100 {
        let message = randombytes(random_usize() % 1000);
        let aad = randombytes(random_usize() % 1000);
        let mls_plaintext = group_alice.create_application_message(&aad, &message);
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
