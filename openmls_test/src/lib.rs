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
        let ciphersuite_name = format!("{:?}", ciphersuite);
        let name = format_ident!("{}_rustcrypto_{}", fn_name, ciphersuite_name);
        let test_fun = quote! {
            #(#attrs)*
            #[allow(non_snake_case)]
            #[test]
            fn #name() {
                use openmls_rust_crypto::OpenMlsRustCrypto;
                use openmls_traits::{types::Ciphersuite, crypto::OpenMlsCrypto, storage::StorageProvider as StorageProviderTrait};

                type Provider = OpenMlsRustCrypto;
                type StorageProvider = <Provider as openmls_traits::OpenMlsProvider>::StorageProvider;
                type StorageError = <StorageProvider as StorageProviderTrait<{openmls_traits::storage::CURRENT_VERSION}>>::Error;

                let _ = pretty_env_logger::try_init();

                let ciphersuite = Ciphersuite::try_from(#val).unwrap();
                let provider = OpenMlsRustCrypto::default();
                let provider = &provider;
                #(#body)*
            }
        };

        test_funs.push(test_fun);
    }

    #[cfg(all(
        feature = "libcrux-provider",
        not(any(
            target_arch = "wasm32",
            all(target_arch = "x86", target_os = "windows")
        ))
    ))]
    {
        let libcrux = openmls_libcrux_crypto::Provider::default();
        let libcrux_ciphersuites = libcrux.crypto().supported_ciphersuites();

        for ciphersuite in libcrux_ciphersuites {
            let val = ciphersuite as u16;
            let ciphersuite_name = format!("{:?}", ciphersuite);
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
