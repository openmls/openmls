use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, Data, DeriveInput, Fields, FieldsUnnamed};

use crate::attrs::extract_storage_tag;

pub(crate) fn serialize(input: TokenStream) -> TokenStream {
    // parse the input
    let input: DeriveInput = parse2(input).unwrap();
    let name = &input.ident;

    // retrieve the enum
    let Data::Enum(data_enum) = &input.data else {
        panic!("only enums are supported");
    };

    // hashset of used storage tags to avoid collisions
    let mut storage_tags = std::collections::HashSet::new();

    let match_arms = data_enum
        .variants
        .iter()
        .map(|variant| {
            // retrieve the variant name
            let variant_name = &variant.ident;

            // get the storage tag
            let storage_tag = extract_storage_tag(variant.attrs.iter()).unwrap_or_else(|| {
                panic!("storage tag not provided for variant {name}::{variant_name}")
            });
            if !storage_tags.insert(storage_tag) {
                panic!("Duplicate storage tags");
            }

            // construct a match arm based on the type
            match &variant.fields {
                Fields::Unit => quote! {
                    #name::#variant_name => s.serialize_unit_variant(
                        stringify!(#name),
                        #storage_tag,
                        stringify!(#variant_name),
                    ),
                },
                Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                    quote! {
                        #name::#variant_name(v) => s.serialize_newtype_variant(
                            stringify!(#name),
                            #storage_tag,
                            stringify!(#variant_name),
                            v
                        ),

                    }
                }
                Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 2 => {
                    quote! {
                        #name::#variant_name(v1, v2) => {
                         let mut tv = s.serialize_tuple_variant(
                                stringify!(#name),
                                #storage_tag,
                                stringify!(#variant_name),
                                2
                            )?;
                            tv.serialize_field(v1)?;
                            tv.serialize_field(v2)?;
                            tv.end()
                        }

                    }
                }
                _ => unimplemented!("fields not supported"),
            }
        })
        .collect::<Vec<_>>();

    quote! {
        impl serde::Serialize for #name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeTupleVariant;
                match self {
                    #(#match_arms)*
                }
            }
        }

    }
}
