#![no_main]
use libfuzzer_sys::fuzz_target;

use openmls::prelude::*;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = MLSCiphertext::decode(&mut cursor);
});
