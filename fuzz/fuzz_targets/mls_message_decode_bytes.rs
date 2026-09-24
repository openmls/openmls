#![no_main]
use libfuzzer_sys::fuzz_target;
use openmls::prelude::{tls_codec::*, *};

// Exercises the DeserializeBytes (byte-slice) path, which recomputes the
// unconsumed remainder from tls_serialized_len. The Deserialize (reader) path
// covered by mls_message_decode does not touch that computation.
fuzz_target!(|data: &[u8]| {
    let _ = MlsMessageIn::tls_deserialize_bytes(data);
});
