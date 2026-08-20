#![no_main]
use libfuzzer_sys::fuzz_target;
use openmls::prelude::{tls_codec::*, *};

// The extension collection decoder enforces uniqueness across the whole list,
// which the single-extension target does not exercise.
fuzz_target!(|data: &[u8]| {
    let _ = Extensions::<AnyObject>::tls_deserialize_bytes(data);
});
