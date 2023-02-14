use super::*;

#[test]
fn test_protocol_version() {
    use crate::versions::ProtocolVersion;
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();
    let mls10_e = mls10_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::try_from(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap())).unwrap(),
        mls10_version
    );
    let default_e = default_version
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    assert_eq!(
        ProtocolVersion::try_from(u16::from_be_bytes(default_e[0..2].try_into().unwrap())).unwrap(),
        default_version
    );
    assert_eq!(u16::from_be_bytes(mls10_e[0..2].try_into().unwrap()), 1);
    assert_eq!(u16::from_be_bytes(default_e[0..2].try_into().unwrap()), 1);
}
