//! Unit test for PathKeys

#[cfg(test)]
use super::{index::NodeIndex, path_keys::*, test_util::*};
#[cfg(test)]
use crate::ciphersuite::*;

#[should_panic]
#[test]
fn test_duplicate_index() {
    fn key() -> HPKEPrivateKey {
        HPKEPrivateKey::new(vec![1, 2, 3, 4, 5, 6])
    }
    let path = [
        NodeIndex::from(1u32),
        NodeIndex::from(2u32),
        NodeIndex::from(3u32),
        NodeIndex::from(1u32),
    ];
    let private_keys = vec![key(), key(), key(), key()];
    let mut path_keys = PathKeys::default();
    path_keys.add(private_keys, &path[..]).unwrap();
}

#[test]
fn test_insert_retrieve() {
    fn key() -> HPKEPrivateKey {
        HPKEPrivateKey::new(vec![1, 2, 3, 4, 5, 6])
    }
    let path = generate_path_u32(2001);
    let private_keys = (0..1000).map(|_| key()).collect();

    let mut path_keys = PathKeys::default();

    // Some random keys
    path_keys.add(private_keys, &path[0..1000]).unwrap();
    // The key we look for
    path_keys
        .add(vec![HPKEPrivateKey::new(vec![6, 6, 6])], &path[1000..1001])
        .unwrap();
    let private_keys = (0..1000).map(|_| key()).collect();
    // A couple more random keys
    path_keys.add(private_keys, &path[1001..2001]).unwrap();

    // Get out the key [6, 6, 6]
    assert_eq!(&[6, 6, 6], path_keys.get(path[1000]).unwrap().as_slice());
}
