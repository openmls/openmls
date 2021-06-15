/// A framework to create integration tests of managed group API.
pub mod managed_utils;
/// A framework to create integration tests of the "raw" mls_group API.
pub mod mls_utils;

#[allow(unused_macros)]
macro_rules! ctest_ciphersuites {
    ($name:ident, test($param_name:ident: $t:ty) $body:block) => {
        test_macros::ctest!(
            $name
            [
                CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
                CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ]
            {
                fn test($param_name: $t) $body
                test(param)
            }
        );
    };
}
