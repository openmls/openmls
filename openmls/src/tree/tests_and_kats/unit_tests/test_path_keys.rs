//! Unit test for PathKeys

use super::test_util::*;
use crate::ciphersuite::*;
use crate::tree::path_keys::*;

#[test]
fn test_insert_retrieve() {
    fn key() -> HpkePrivateKey {
        HpkePrivateKey::new(vec![1, 2, 3, 4, 5, 6])
    }
    let path = generate_path_u32(2001);
    let private_keys = (0..1000).map(|_| key()).collect();

    let mut path_keys = PathKeys::default();

    // Some random keys
    path_keys.add(private_keys, &path[0..1000]);
    // The key we look for
    path_keys.add(vec![HpkePrivateKey::new(vec![6, 6, 6])], &path[1000..1001]);
    let private_keys = (0..1000).map(|_| key()).collect();
    // A couple more random keys
    path_keys.add(private_keys, &path[1001..2001]);

    // Get out the key [6, 6, 6]
    assert_eq!(
        &[6, 6, 6],
        path_keys
            .get(path[1000])
            .expect("An unexpected error occurred.")
            .as_slice()
    );
}
