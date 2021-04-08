use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use quote::quote;
use syn::{
    parse::Result,
    parse::{Parse, ParseStream},
    parse_macro_input, Block, Expr, ExprArray, Member,
};

struct TestInput {
    test_name: Ident,
    // An array to iterate over.
    parameters: ExprArray,
    body: Block,
}

impl Parse for TestInput {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            test_name: input.parse()?,
            parameters: input.parse()?,
            body: input.parse()?,
        })
    }
}

#[proc_macro]
pub fn ctest(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TestInput);
    impl_ciphersuite_tests(input, quote! {})
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
}

fn impl_ciphersuite_tests(
    input: TestInput,
    test_attribute: proc_macro2::TokenStream,
) -> TokenStream {
    let ast = input.body.clone();
    let test_name = input.test_name.clone();
    let num_parameters = input.parameters.elems.len();
    let params = input.parameters.clone();
    let tests = (0..num_parameters).map(|i| {
        let param_name = match &input.parameters.elems[i] {
            Expr::Field(f) => match &f.member {
                Member::Named(n) => n.to_string(),
                _ => panic!("Unsupported enum with unnamed members"),
            },
            Expr::Path(p) => p.path.segments.last().unwrap().ident.to_string(),
            _ => panic!("Unexpected input"),
        };
        let test_name = Ident::new(
            &format!("{}_{}", test_name.to_string(), param_name),
            Span::call_site(),
        );
        quote! {
            #[test]
            #test_attribute
            fn #test_name () {
                let param = #params[#i].clone();
                #ast
            }
        }
    });
    let gen = quote! {
        #(#tests)*
    };
    gen.into()
}
