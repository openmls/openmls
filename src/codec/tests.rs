use crate::{
    ciphersuite::{Ciphersuite, HPKEPublicKey},
    config::ProtocolVersion,
};

use super::{Codec, CodecError, TlsSerializer, TlsSize};

#[test]
fn serializer() {
    let protocol_version = ProtocolVersion::Mls10;
    let ciphersuite = Ciphersuite::default().name();
    let hpke_public_key = HPKEPublicKey::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);

    let mut len = 0;
    len += protocol_version.serialized_len();
    len += ciphersuite.serialized_len();
    len += hpke_public_key.serialized_len();

    let mut serialized = Vec::with_capacity(len);
    (protocol_version as u8).encode(&mut serialized).unwrap();
    (ciphersuite as u16).encode(&mut serialized).unwrap();
    (hpke_public_key.as_slice().len() as u16)
        .encode(&mut serialized)
        .unwrap();
    serialized.extend_from_slice(hpke_public_key.as_slice());

    assert_eq!(
        vec![0x01, 0x00, 0x01, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],
        serialized
    );
}
