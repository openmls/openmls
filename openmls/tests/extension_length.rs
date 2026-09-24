//! Regression test for an off-by-one in the extension length calculation.
//!
//! An extension whose data is exactly 0x3fff (16383) bytes long is encoded with
//! a 2-byte variable-length prefix, but `Extension::tls_serialized_len` used to
//! report a 4-byte prefix. That made the reported length exceed the bytes
//! actually consumed, so `Extension::tls_deserialize_exact_bytes` indexed past
//! the end of the input and panicked.

use openmls::prelude::tls_codec::*;
use openmls::prelude::*;

/// Canonical wire bytes for an extension with an unknown type and `data_len`
/// bytes of extension data.
fn unknown_extension(data_len: usize) -> Vec<u8> {
    let mut out = 0x0A0Au16.to_be_bytes().to_vec();
    let data = VLBytes::from(vec![0u8; data_len]);
    out.extend_from_slice(
        &data
            .tls_serialize_detached()
            .expect("serializing extension data"),
    );
    out
}

#[test]
fn extension_length_matches_wire_across_varint_boundaries() {
    // Values straddling the 1/2/4-byte variable-length prefix boundaries.
    for data_len in [0, 63, 64, 16382, 16383, 16384] {
        let wire = unknown_extension(data_len);

        let extension = Extension::tls_deserialize(&mut wire.as_slice())
            .expect("extension decodes via the reader path");
        assert_eq!(
            extension.tls_serialized_len(),
            wire.len(),
            "tls_serialized_len must equal the bytes on the wire (data_len={data_len})",
        );

        // The byte-slice path recomputes the remainder from tls_serialized_len,
        // so a wrong length crashes here instead of returning cleanly.
        Extension::tls_deserialize_exact_bytes(&wire)
            .expect("extension decodes via the byte-slice path");
    }
}
