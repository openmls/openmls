use tls_codec::{Serialize, TlsVecU16};
use tls_codec_derive::TlsSerialize;

#[derive(TlsSerialize, Debug)]
#[allow(dead_code)]
#[repr(u16)]
pub enum ExtensionType {
    Reserved = 0,
    Capabilities = 1,
    Lifetime = 2,
    KeyID = 3,
    ParentHash = 4,
    RatchetTree = 5,
    SomethingElse = 500,
}

#[derive(TlsSerialize, Debug)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: TlsVecU16<u8>,
}

#[test]
fn simple_enum() {
    let serialized = ExtensionType::KeyID.serialize_detached().unwrap();
    assert_eq!(vec![0, 3], serialized);
    let serialized = ExtensionType::SomethingElse.serialize_detached().unwrap();
    assert_eq!(vec![1, 244], serialized);
}

#[test]
fn simple_struct() {
    let extension = ExtensionStruct {
        extension_type: ExtensionType::KeyID,
        extension_data: TlsVecU16::from_slice(&[1, 2, 3, 4, 5]),
    };
    let serialized = extension.serialize_detached().unwrap();
    assert_eq!(vec![0, 3, 0, 5, 1, 2, 3, 4, 5], serialized);
}

#[test]
fn byte_arrays() {
    let x = [0u8, 1, 2, 3];
    let serialized = x.serialize_detached().unwrap();
    assert_eq!(vec![0, 1, 2, 3], serialized);
}
