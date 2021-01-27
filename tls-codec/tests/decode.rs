use tls_codec::{Cursor, Deserialize, TlsVecU8};

#[test]
fn deserialize_primitives() {
    let b = [77, 88, 1, 99];
    let cursor = Cursor::new(&b);

    let a = u8::tls_deserialize(&cursor).expect("Unable to tls_deserialize");
    assert_eq!(77, a);
    let a = u8::tls_deserialize(&cursor).expect("Unable to tls_deserialize");
    assert_eq!(88, a);
    let a = u16::tls_deserialize(&cursor).expect("Unable to tls_deserialize");
    assert_eq!(355, a);

    // It's empty now.
    assert!(u8::tls_deserialize(&cursor).is_err())
}

#[test]
fn deserialize_tls_vec() {
    let b = [1, 4, 77, 88, 1, 99];
    let cursor = Cursor::new(&b);

    let a = u8::tls_deserialize(&cursor).expect("Unable to tls_deserialize");
    assert_eq!(1, a);
    let v = TlsVecU8::<u8>::tls_deserialize(&cursor).expect("Unable to tls_deserialize");
    assert_eq!(&[77, 88, 1, 99], v.as_slice());

    // It's empty now.
    assert!(u8::tls_deserialize(&cursor).is_err());
}
