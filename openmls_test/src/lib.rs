use std::env;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsProvider};
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn};

/// Mandatory-to-implement ciphersuite per RFC 9420.
/// Used as the sole default when the `all-ciphersuites` feature is off.
const MTI_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Environment variable that restricts the expansion to a subset of the
/// ciphersuites, written as `index/total` with a 1-based index.
const SHARD_ENV: &str = "OPENMLS_TEST_CIPHERSUITE_SHARD";

/// One slice of the ciphersuites a provider supports.
///
/// A test body is copied once per provider and ciphersuite, so the work a
/// single `rustc` has to do grows with the number of ciphersuites in the
/// expansion. Sharding spreads that over several `cargo test` invocations,
/// which is what keeps the `all-ciphersuites` runs within the memory of a CI
/// runner. Every ciphersuite lands in exactly one shard, so running all
/// `total` shards covers the same set as running unsharded.
struct Shard {
    index: usize,
    total: usize,
}

impl Shard {
    /// Reads the shard from the environment.
    ///
    /// Returns `Ok(None)` when the variable is unset or empty, and a message
    /// meant for `compile_error!` when it is malformed.
    fn from_env() -> Result<Option<Self>, String> {
        let Ok(value) = env::var(SHARD_ENV) else {
            return Ok(None);
        };

        Self::parse(&value)
    }

    /// Parses the `index/total` form the environment variable takes.
    fn parse(value: &str) -> Result<Option<Self>, String> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }

        let malformed = || format!("{SHARD_ENV} must read `index/total`, got `{value}`");

        let (index, total) = value.split_once('/').ok_or_else(malformed)?;
        let index: usize = index.trim().parse().map_err(|_| malformed())?;
        let total: usize = total.trim().parse().map_err(|_| malformed())?;

        if index == 0 || index > total {
            return Err(format!(
                "{SHARD_ENV} needs `1 <= index <= total`, got `{value}`"
            ));
        }

        Ok(Some(Self { index, total }))
    }

    /// Keeps every `total`-th ciphersuite, starting at `index`.
    ///
    /// Picking them in strides rather than in one contiguous block spreads the
    /// slow ciphersuites over the shards instead of piling them into one.
    fn select(&self, ciphersuites: Vec<Ciphersuite>) -> Vec<Ciphersuite> {
        ciphersuites
            .into_iter()
            .skip(self.index - 1)
            .step_by(self.total)
            .collect()
    }
}

/// Returns the ciphersuites a provider's tests should be expanded over.
///
/// Without the `all-ciphersuites` feature, this collapses to the MTI
/// ciphersuite so each `#[openmls_test]` produces one test per provider.
/// With the feature enabled, every supported ciphersuite is emitted, which
/// matches the historical behaviour and is intended for on-demand runs
/// (nightly CI, release validation). A shard narrows the result further.
fn filter_ciphersuites(
    provider_supported: Vec<Ciphersuite>,
    shard: Option<&Shard>,
) -> Vec<Ciphersuite> {
    let ciphersuites = if cfg!(feature = "all-ciphersuites") {
        provider_supported
    } else if provider_supported.contains(&MTI_CIPHERSUITE) {
        vec![MTI_CIPHERSUITE]
    } else {
        // The provider does not advertise the MTI ciphersuite. Emit no
        // tests for it rather than silently using something else.
        Vec::new()
    };

    match shard {
        Some(shard) => shard.select(ciphersuites),
        None => ciphersuites,
    }
}

#[proc_macro_attribute]
pub fn openmls_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    let attrs = func.attrs;
    let sig = func.sig;
    let fn_name = sig.ident;
    let body = func.block.stmts;

    let shard = match Shard::from_env() {
        Ok(shard) => shard,
        Err(message) => return quote! { compile_error!(#message); }.into(),
    };

    let rc = OpenMlsRustCrypto::default();

    let rc_ciphersuites = filter_ciphersuites(rc.crypto().supported_ciphersuites(), shard.as_ref());

    let mut test_funs = Vec::new();

    for ciphersuite in rc_ciphersuites {
        let val = ciphersuite as u16;
        let ciphersuite_name = format!("{ciphersuite:?}");
        let name = format_ident!("{}_rustcrypto_{}", fn_name, ciphersuite_name);
        let test_fun = quote! {
            #(#attrs)*
            #[allow(non_snake_case)]
            #[test]
            fn #name() {
                use openmls_rust_crypto::{OpenMlsRustCrypto, MemoryStorage};
                use openmls_traits::{types::Ciphersuite, crypto::OpenMlsCrypto, storage::StorageProvider as StorageProviderTrait};
                use openmls_traits::OpenMlsProvider;

                type Provider = OpenMlsRustCrypto;
                type StorageProvider = <Provider as openmls_traits::OpenMlsProvider>::StorageProvider;
                type StorageError = <StorageProvider as StorageProviderTrait<{openmls_traits::storage::CURRENT_VERSION}>>::Error;

                let _ = pretty_env_logger::try_init();

                let ciphersuite = Ciphersuite::try_from(#val).unwrap();

                #(#body)*
            }
        };

        test_funs.push(test_fun);
    }

    #[cfg(all(feature = "sqlite-provider", not(target_arch = "wasm32",)))]
    {
        let rc_ciphersuites =
            filter_ciphersuites(rc.crypto().supported_ciphersuites(), shard.as_ref());
        for ciphersuite in rc_ciphersuites {
            let val = ciphersuite as u16;
            let ciphersuite_name = format!("{ciphersuite:?}");
            let name = format_ident!("{}_sqlite_{}", fn_name, ciphersuite_name);
            let test_fun = quote! {
                #(#attrs)*
                #[allow(non_snake_case)]
                #[test]
                fn #name() {
                    use openmls_rust_crypto::RustCrypto;
                    use openmls_sqlite_storage::{SqliteStorageProvider, Codec, Connection};
                    use openmls_traits::OpenMlsProvider;
                    use openmls_traits::{types::Ciphersuite, crypto::OpenMlsCrypto, storage::StorageProvider as StorageProviderTrait};

                    #[derive(Default)]
                    pub struct JsonCodec;

                    impl Codec for JsonCodec {
                        type Error = serde_json::Error;

                        fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
                            serde_json::to_vec(value)
                        }

                        fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
                            serde_json::from_slice(slice)
                        }
                    }

                    struct OpenMlsSqliteTestProvider {
                        crypto: RustCrypto,
                        storage: SqliteStorageProvider<JsonCodec, Connection>,
                    }

                    impl Default for OpenMlsSqliteTestProvider {
                        fn default() -> Self {
                            let connection = Connection::open_in_memory().unwrap();
                            let mut storage = SqliteStorageProvider::new(connection);
                            storage.run_migrations().unwrap();
                            Self {
                                crypto: RustCrypto::default(),
                                storage,
                            }
                        }
                    }

                    impl OpenMlsProvider for OpenMlsSqliteTestProvider {
                        type CryptoProvider = RustCrypto;
                        type RandProvider = RustCrypto;
                        type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

                        fn storage(&self) -> &Self::StorageProvider {
                            &self.storage
                        }

                        fn crypto(&self) -> &Self::CryptoProvider {
                            &self.crypto
                        }

                        fn rand(&self) -> &Self::RandProvider {
                            &self.crypto
                        }
                    }

                    type Provider = OpenMlsSqliteTestProvider;
                    type StorageProvider = <Provider as openmls_traits::OpenMlsProvider>::StorageProvider;
                    type StorageError = <StorageProvider as StorageProviderTrait<{openmls_traits::storage::CURRENT_VERSION}>>::Error;

                    let _ = pretty_env_logger::try_init();

                    let ciphersuite = Ciphersuite::try_from(#val).unwrap();

                    #(#body)*
                }
            };

            test_funs.push(test_fun);
        }
    }

    #[cfg(all(
        feature = "libcrux-provider",
        not(all(target_arch = "x86", target_os = "windows"))
    ))]
    {
        let libcrux = openmls_libcrux_crypto::Provider::default();
        let libcrux_ciphersuites =
            filter_ciphersuites(libcrux.crypto().supported_ciphersuites(), shard.as_ref());

        for ciphersuite in libcrux_ciphersuites {
            let val = ciphersuite as u16;
            let ciphersuite_name = format!("{ciphersuite:?}");
            let name = format_ident!("{}_libcrux_{}", fn_name, ciphersuite_name);
            let test_fun = quote! {
                #(#attrs)*
                #[allow(non_snake_case)]
                #[test]
                fn #name() {
                    use openmls_libcrux_crypto::Provider as OpenMlsLibcrux;
                    use openmls_traits::{types::Ciphersuite, prelude::*};

                    type Provider = OpenMlsLibcrux;
                    type StorageProvider = <Provider as openmls_traits::OpenMlsProvider>::StorageProvider;
                    type StorageError = <StorageProvider as openmls_traits::storage::StorageProvider<{openmls_traits::storage::CURRENT_VERSION}>>::Error;

                    let _ = pretty_env_logger::try_init();

                    let ciphersuite = Ciphersuite::try_from(#val).unwrap();

                    // When cross-compiling the supported ciphersuites may be wrong.
                    // They are set at compile-time.
                    if OpenMlsLibcrux::default().crypto().supports(ciphersuite).is_err() {
                        eprintln!("Skipping unsupported ciphersuite {ciphersuite:?}.");
                        return;
                    }

                    #(#body)*
                }
            };

            test_funs.push(test_fun);
        }
    }

    let out = quote! {
        #(#test_funs)*
    };

    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_and_empty_shards_select_everything() {
        assert!(Shard::parse("").unwrap().is_none());
        assert!(Shard::parse("  ").unwrap().is_none());
    }

    #[test]
    fn malformed_shards_are_rejected() {
        for value in ["1", "1/", "one/three", "0/3", "4/3", "1/0", "-1/3"] {
            assert!(Shard::parse(value).is_err(), "accepted `{value}`");
        }
    }

    #[test]
    fn every_ciphersuite_is_in_exactly_one_shard() {
        let all = OpenMlsRustCrypto::default()
            .crypto()
            .supported_ciphersuites();

        for total in 1..=4 {
            let mut sharded = Vec::new();
            for index in 1..=total {
                let shard = Shard::parse(&format!("{index}/{total}")).unwrap().unwrap();
                sharded.extend(shard.select(all.clone()));
            }

            sharded.sort();
            let mut expected = all.clone();
            expected.sort();
            assert_eq!(sharded, expected, "with {total} shards");
        }
    }
}
