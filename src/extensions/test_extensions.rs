//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.
//!

use super::*;
use crate::codec::{Codec, Cursor};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for maelstrom.
    let extension_bytes = [0, 1, 0, 16, 1, 1, 6, 0, 1, 0, 3, 0, 2, 6, 0, 1, 0, 2, 0, 3];

    let ext = CapabilitiesExtension::default();
    let ext_struct = ext.to_extension_struct();

    // Check that decoding works
    let capabiblities_extension_struct =
        ExtensionStruct::decode(&mut Cursor::new(&extension_bytes)).unwrap();
    assert_eq!(ext_struct, capabiblities_extension_struct);

    // Encoding creates the expected bytes.
    assert_eq!(
        &extension_bytes[..],
        &ext_struct.encode_detached().unwrap()[..]
    );
}

#[test]
fn key_package_id() {
    // A key package extension with the default values for maelstrom.
    let extension_bytes = [0, 1, 0, 16, 1, 1, 6, 0, 1, 0, 3, 0, 2, 6, 0, 1, 0, 2, 0, 3];

    let ext = CapabilitiesExtension::default();
    let ext_struct = ext.to_extension_struct();

    // Check that decoding works
    let capabiblities_extension_struct =
        ExtensionStruct::decode(&mut Cursor::new(&extension_bytes)).unwrap();
    assert_eq!(ext_struct, capabiblities_extension_struct);

    // Encoding creates the expected bytes.
    assert_eq!(
        &extension_bytes[..],
        &ext_struct.encode_detached().unwrap()[..]
    );
}

#[test]
fn lifetime() {
    const LIFETIME_1_MINUTE: u64 = 60;
    const LIFETIME_1_HOUR: u64 = 60 * LIFETIME_1_MINUTE;

    // A freshly created extensions must be valid.
    let ext = LifetimeExtension::new(LIFETIME_1_HOUR);
    assert!(ext.is_valid());

    // An extension without lifetime is invalid (waiting for 1 second).
    let ext = LifetimeExtension::new(0);
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!ext.is_valid());
}
