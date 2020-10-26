#![no_main]
use libfuzzer_sys::fuzz_target;

use maelstrom::{
    codec::{Codec, Cursor},
    key_packages::KeyPackage,
};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = KeyPackage::decode(&mut cursor);
});
