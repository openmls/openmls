use openmls_libcrux::OpenMlsLibcrux;
use openmls_rust_crypto::{
    openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider},
    OpenMlsRustCrypto,
};
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
    let libcrux = OpenMlsLibcrux::default();

    let rc_ciphersuites = rc.crypto().supported_ciphersuites();
    let libcrux_ciphersuites = libcrux.crypto().supported_ciphersuites();

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
                use openmls_rust_crypto::openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

                let ciphersuite = Ciphersuite::try_from(#val).unwrap();
                let backend = OpenMlsRustCrypto::default();
                let backend = &backend;
                #(#body)*
            }
        };

        test_funs.push(test_fun);
    }

    for ciphersuite in libcrux_ciphersuites {
        let val = ciphersuite as u16;
        let ciphersuite_name = format!("{:?}", ciphersuite);
        let name = format_ident!("{}_libcrux_{}", fn_name, ciphersuite_name);
        let test_fun = quote! {
            #(#attrs)*
            #[allow(non_snake_case)]
            #[test]
            fn #name() {
                use openmls_libcrux::OpenMlsLibcrux;
                use openmls_libcrux::openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};

                let ciphersuite = Ciphersuite::try_from(#val).unwrap();
                let backend = OpenMlsLibcrux::default();
                let backend = &backend;
                #(#body)*
            }
        };

        test_funs.push(test_fun);
    }

    let out = quote! {
        #(#test_funs)*
    };

    out.into()
}
