use tls_codec::{Serialize, TlsVecU16};

#[test]
fn serialize_primitives() {
    let mut v = Vec::new();
    77u8.tls_serialize(&mut v).expect("Error encoding u8");
    88u8.tls_serialize(&mut v).expect("Error encoding u8");
    355u16.tls_serialize(&mut v).expect("Error encoding u16");
    let b = [77u8, 88, 1, 99];
    assert_eq!(&b[..], &v[..]);
}

#[test]
fn serialize_tls_vec() {
    let mut v = Vec::new();
    1u8.tls_serialize(&mut v).expect("Error encoding u8");
    TlsVecU16::<u8>::from_slice(&[77, 88, 1, 99])
        .tls_serialize(&mut v)
        .expect("Error encoding u8");

    let b = [1u8, 0, 4, 77, 88, 1, 99];
    assert_eq!(&b[..], &v[..]);
}
