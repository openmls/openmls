use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn openmls_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    let attrs = func.attrs;
    let sig = func.sig;
    let fn_name = sig.ident;
    let body = func.block.stmts;

    let rc = OpenMlsRustCrypto::default();

    let rc_ciphersuites = rc.crypto().supported_ciphersuites();

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
                let provider = OpenMlsRustCrypto::default();
                let provider: &Provider = &provider;
                let storage: &MemoryStorage = provider.storage();
                #(#body)*
            }
        };

        test_funs.push(test_fun);
    }

    #[cfg(all(feature = "sqlite-provider", not(target_arch = "wasm32",)))]
    {
        let rc_ciphersuites = rc.crypto().supported_ciphersuites();
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
                    let provider = OpenMlsSqliteTestProvider::default();
                    let provider = &provider;
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
        let libcrux_ciphersuites = libcrux.crypto().supported_ciphersuites();

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
                    let provider = OpenMlsLibcrux::default();

                    // When cross-compiling the supported ciphersuites may be wrong.
                    // They are set at compile-time.
                    if provider.crypto().supports(ciphersuite).is_err() {
                        eprintln!("Skipping unsupported ciphersuite {ciphersuite:?}.");
                        return;
                    }

                    let provider = &provider;
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
