use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{
    parse::Result,
    parse::{Parse, ParseStream},
    parse_macro_input, Block,
};

struct TestInput {
    test_name: Ident,
    body: Block,
}

impl Parse for TestInput {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            test_name: input.parse()?,
            body: input.parse()?,
        })
    }
}

#[proc_macro]
pub fn ctest(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TestInput);
    impl_ciphersuite_tests(input, quote! {}).unwrap()
}

#[proc_macro]
pub fn ctest_panic(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TestInput);
    impl_ciphersuite_tests(
        input,
        quote! {
            #[should_panic]
        },
    )
    .unwrap()
}

fn impl_ciphersuite_tests(
    input: TestInput,
    test_attribute: proc_macro2::TokenStream,
) -> Result<TokenStream> {
    let ast = input.body;
    let test_name = input.test_name;
    let tests = openmls::config::Config::supported_ciphersuite_names()
        .into_iter()
        .map(|&ciphersuite_name| {
            let ciphersuite_code = ciphersuite_name as u16;
            let test_name = Ident::new(
                &format!("{}_{}", test_name.to_string(), ciphersuite_name),
                Span::call_site(),
            );
            quote! {
                #[test]
                #test_attribute
                fn #test_name () {
                    let _ciphersuite_code = #ciphersuite_code;
                    #ast
                }
            }
        });
    let gen = quote! {
        #(#tests)*
    };
    Ok(gen.into())
}
