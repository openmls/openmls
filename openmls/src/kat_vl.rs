//! ## Vector Deserialization
//!
//! Parameters:
//! * Header for variable length encoded Vector
//! * The encoded length
//!
//!
//! Format:
//! ``` text
//! [
//!   {
//!     "vlbytes_header": /* hex-encoded binary data */,
//!     "length": /* integer for the encoded size */
//!   },
//!   ...
//! ]
//! ```
//!
//! This Test contains a List of Serialized Variable Length Headers (`vlbytes_header`)  and a length.
//!
//! Verification:
//! * Decode the `vlbytes_header`
//! * Verify that the decoded length matches the given `length`

use serde::Deserialize;
use tls_codec::{Deserialize as TlsDeserialize, VLBytes};

#[derive(Deserialize)]
struct TestElement {
    #[serde(with = "hex")]
    vlbytes_header: Vec<u8>,
    length: u32,
}

fn run_test_vector(element: TestElement) -> Result<(), String> {
    let total_length = element.vlbytes_header.len() + element.length as usize;
    let mut serialized_vec = vec![0; total_length];
    serialized_vec[..element.vlbytes_header.len()].copy_from_slice(&element.vlbytes_header);
    let deserialized_vec = VLBytes::tls_deserialize_exact(serialized_vec.as_slice()).unwrap();
    let deserialized_vec_len = deserialized_vec.as_slice().len();

    if deserialized_vec_len != element.length as usize {
        panic!(
            "Deserialized length does not match expected length.\n\
                 Expected: {0}\n\
                 Actual: {1}",
            element.length, deserialized_vec_len
        );
    }
    Ok(())
}

#[test]
fn read_test_vectors_deserialize() {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<TestElement> = read_json!("../test_vectors/deserialization.json");

    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking deserialization test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
