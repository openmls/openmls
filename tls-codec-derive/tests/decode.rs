use tls_codec::{Cursor, Deserialize, Serialize, TlsVecU16, TlsVecU8};
use tls_codec_derive::{TlsDeserialize, TlsSerialize};

#[derive(TlsDeserialize, Debug, PartialEq, Clone, Copy, TlsSerialize)]
#[allow(dead_code)]
#[repr(u16)]
pub enum ExtensionType {
    Reserved = 0,
    Capabilities = 1,
    Lifetime = 2,
    KeyId = 3,
    ParentHash = 4,
    RatchetTree = 5,
    SomethingElse = 500,
}

#[derive(TlsDeserialize, Debug, PartialEq, TlsSerialize)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: TlsVecU16<u8>,
}

#[derive(TlsDeserialize, Debug, PartialEq, TlsSerialize)]
pub struct ExtensionTypeVec {
    data: TlsVecU8<ExtensionType>,
}

#[derive(TlsDeserialize, Debug, PartialEq, TlsSerialize)]
pub struct ArrayWrap {
    data: [u8; 8],
}

#[test]
fn simple_enum() {
    let b = [0, 5];
    let deserialized = ExtensionType::tls_deserialize_detached(&b).unwrap();
    assert_eq!(ExtensionType::RatchetTree, deserialized);

    let b = [0, 5, 1, 244, 0, 1];
    let variants = [
        ExtensionType::RatchetTree,
        ExtensionType::SomethingElse,
        ExtensionType::Capabilities,
    ];
    let c = Cursor::new(&b);
    for variant in variants.iter() {
        let deserialized = ExtensionType::tls_deserialize(&c).unwrap();
        assert_eq!(variant, &deserialized);
    }
}

#[test]
fn simple_struct() {
    let b = [0, 3, 0, 5, 1, 2, 3, 4, 5];
    let extension = ExtensionStruct {
        extension_type: ExtensionType::KeyId,
        extension_data: TlsVecU16::from_slice(&[1, 2, 3, 4, 5]),
    };
    let deserialized = ExtensionStruct::tls_deserialize_detached(&b).unwrap();
    assert_eq!(extension, deserialized);

    let b = [8, 0, 1, 0, 2, 0, 3, 1, 244];
    let extension = ExtensionTypeVec {
        data: TlsVecU8::from_slice(&[
            ExtensionType::Capabilities,
            ExtensionType::Lifetime,
            ExtensionType::KeyId,
            ExtensionType::SomethingElse,
        ]),
    };
    let deserialized = ExtensionTypeVec::tls_deserialize_detached(&b).unwrap();
    assert_eq!(extension, deserialized);
}

#[test]
fn byte_arrays() {
    let x = [0u8, 1, 2, 3];
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(x.to_vec(), serialized);

    let y = <[u8; 4]>::tls_deserialize_detached(&serialized).unwrap();
    assert_eq!(y, x);

    let x = [0u8, 1, 2, 3, 7, 6, 5, 4];
    let w = ArrayWrap { data: x };
    let serialized = x.tls_serialize_detached().unwrap();
    assert_eq!(x.to_vec(), serialized);

    let y = ArrayWrap::tls_deserialize_detached(&serialized).unwrap();
    assert_eq!(y, w);
}
