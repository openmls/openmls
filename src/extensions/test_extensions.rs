//! # Extensions Unit tests
//! Some basic unit tests for extensions
//! Proper testing is done through the public APIs.

use super::*;
use crate::codec::{Codec, Cursor};

#[test]
fn capabilities() {
    // A capabilities extension with the default values for openmls.
    let extension_bytes = [0, 1, 0, 16, 1, 1, 6, 0, 1, 0, 3, 0, 2, 6, 0, 1, 0, 2, 0, 3];

    let ext = CapabilitiesExtension::default();
    let ext_struct = ext.to_extension_struct();

    // Check that decoding works
    let capabilities_extension_struct =
        ExtensionStruct::decode(&mut Cursor::new(&extension_bytes)).unwrap();
    assert_eq!(ext_struct, capabilities_extension_struct);

    // Encoding creates the expected bytes.
    assert_eq!(
        &extension_bytes[..],
        &ext_struct.encode_detached().unwrap()[..]
    );
}

#[test]
fn key_package_id() {
    // A key package extension with the default values for openmls.
    let data = [0, 8, 1, 2, 3, 4, 5, 6, 6, 6];
    let kpi = KeyIDExtension::new(&data[2..]);
    assert_eq!(ExtensionType::KeyID, kpi.get_type());

    let kpi_from_bytes = KeyIDExtension::new_from_bytes(&data).unwrap();
    assert_eq!(kpi, kpi_from_bytes);

    let extension_struct = kpi.to_extension_struct();
    assert_eq!(ExtensionType::KeyID, extension_struct.extension_type);
    assert_eq!(&data[..], &extension_struct.extension_data[..]);
}

#[test]
fn lifetime() {
    // A freshly created extensions must be valid.
    let ext = LifetimeExtension::default();
    assert!(ext.is_valid());

    // An extension without lifetime is invalid (waiting for 1 second).
    let ext = LifetimeExtension::new(0);
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(!ext.is_valid());
}
