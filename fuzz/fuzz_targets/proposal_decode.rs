#![no_main]
use libfuzzer_sys::fuzz_target;
use openmls::prelude::{tls_codec::*, *};

fuzz_target!(|data: &[u8]| {
    let _ = ProposalIn::tls_deserialize(&mut &data[..]);
});
