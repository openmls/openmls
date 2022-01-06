#![no_main]
use libfuzzer_sys::fuzz_target;

use openmls::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = MlsMessageIn::try_from_bytes(data);
});
