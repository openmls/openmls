//! A framework to create integration tests of the "raw" mls_group API.
 
pub use openmls_traits::OpenMlsCryptoProvider;
pub use rstest_reuse::{self, *};
pub use rstest::*;
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

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm")
))]
pub use evercrypt_backend::OpenMlsEvercrypt;

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm"
))]
pub use openmls_rust_crypto::OpenMlsRustCrypto;

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm"
))]
#[template]
#[rstest(ciphersuite, backend, 
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap(), &OpenMlsRustCrypto::default()),
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256).unwrap(), &OpenMlsRustCrypto::default()),
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519).unwrap(), &OpenMlsRustCrypto::default()),
  )
]
fn ciphersuites_and_backends(#[case] ciphersuite: &Ciphersuite, #[case] backend: &impl OpenMlsCryptoProvider) {}


#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm")
))]
#[template]
#[rstest(ciphersuite, backend, 
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap(), &OpenMlsEvercrypt::default()),
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256).unwrap(), &OpenMlsEvercrypt::default()),
    case(&Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519).unwrap(), &OpenMlsEvercrypt::default()),
  )
]
fn ciphersuites_and_backends(#[case] ciphersuite: &Ciphersuite, #[case] backend: &impl OpenMlsCryptoProvider) {}

