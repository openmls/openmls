mod test_utils;
use test_utils::*;

use maelstrom::ciphersuite::*;
use maelstrom::creds::*;
use maelstrom::group::*;

#[test]
fn padding() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519);
    let alice_identity = Identity::new(ciphersuite, vec![1, 2, 3]);

    let config = GROUP_CONFIG_DEFAULT;
    let mut group_alice = Group::new(alice_identity, GroupId::random(), config);

    for _ in 0..100 {
        let message = randombytes(random_usize() % 1000);
        let aad = randombytes(random_usize() % 1000);
        let mls_plaintext = group_alice.create_application_message(&message, Some(&aad));
        let encrypted_message = group_alice.encrypt(&mls_plaintext);
        let length = encrypted_message.len();
        let overflow = length % (config.padding_block_size as usize);
        if overflow != 0 {
            panic!(
                "Error: padding overflow of {} bytes, message length: {}, padding block size: {}",
                overflow, length, config.padding_block_size
            );
        }
    }
}
