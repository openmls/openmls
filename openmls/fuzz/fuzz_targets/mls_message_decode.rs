#![no_main]
use libfuzzer_sys::fuzz_target;
use openmls::prelude::*;
use tls_codec::{Deserialize, Serialize, Size};

fuzz_target!(|data: &[u8]| {
    let mut slice = data;

    // Deserialization must not panic.
    if let Ok(mls_message_in) = MlsMessageIn::tls_deserialize(&mut slice) {
        // The (real) amount of consumed bytes must be equal to what `tls_serialized_len` reports.
        {
            let got_read_from_tls_codec = mls_message_in.tls_serialized_len();
            let got_read_from_slice = data.len() - slice.len();
            // TODO(xxxx): This fails.
            // assert_eq!(got_read_from_tls_codec, got_read_from_slice);
        }

        // Serialization and Deserialization must be inverses of each other.
        {
            let serialized_mls_message_in = mls_message_in.tls_serialize_detached().unwrap();

            // TODO(xxxx): This fails, too.
            assert_eq!(
                &data[..mls_message_in.tls_serialized_len()],
                &serialized_mls_message_in[..]
            );
        }
    }
});
