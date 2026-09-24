#![no_main]
use libfuzzer_sys::fuzz_target;
use openmls::prelude::{tls_codec::*, *};

// Extensions are nested inside key packages, leaf nodes, group info and
// GroupContextExtensions proposals, and are decoded from unauthenticated wire
// bytes. Fuzz the extension decoder directly so failures are not masked by the
// structure of an enclosing message.
fuzz_target!(|data: &[u8]| {
    let _ = Extension::tls_deserialize_bytes(data);
});
