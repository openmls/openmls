//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.
//!

use super::*;
use crate::codec::{Codec, Cursor};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for maelstrom.
    let extension_bytes = [0, 1, 0, 12, 1, 1, 6, 0, 1, 0, 3, 0, 2, 2, 0, 2];

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
    let extension_bytes = [0, 1, 0, 12, 1, 1, 6, 0, 1, 0, 3, 0, 2, 2, 0, 2];

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
