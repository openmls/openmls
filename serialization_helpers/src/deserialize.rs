use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, Data, DeriveInput, Fields, FieldsUnnamed, Ident};

use crate::attrs::extract_storage_tag;

fn build_name_ident(name: &Ident, suffix: &str) -> Ident {
    Ident::new(&format!("{name}{suffix}"), name.span())
}

pub(crate) fn deserialize(input: TokenStream) -> TokenStream {
    // parse the input
    let input: DeriveInput = parse2(input).expect("error parsing input");
    let name = &input.ident;

    // retrieve the enum
    let Data::Enum(data_enum) = &input.data else {
        panic!("only enums are supported");
    };

    // hashset of used storage tags to avoid collisions
    let mut storage_tags = std::collections::HashSet::new();

    // construct names for visitors
    let non_human_readable_visitor = build_name_ident(name, "VisitorNonHumanReadable");
    let human_readable_visitor = build_name_ident(name, "VisitorHumanReadable");
    let tuple_visitor_name = build_name_ident(name, "TupleVisitor");

    let mut variant_names = vec![];
    let mut match_arms_non_self_describing = vec![];
    let mut match_arms_self_describing = vec![];
    for variant in data_enum.variants.iter() {
        // retrieve the variant name
        let variant_name = &variant.ident;
        let variant_name_str = variant_name.to_string();
        variant_names.push(variant_name_str.clone());

        // get the storage tag
        let storage_tag = extract_storage_tag(variant.attrs.iter()).unwrap_or_else(|| {
            panic!("storage tag not provided for variant {name}::{variant_name}")
        });

        // check for duplicates
        if !storage_tags.insert(storage_tag) {
            panic!("Duplicate storage tags");
        }

        let unit_variant_handling = quote! {
            access.unit_variant()?;
            Ok(#name::#variant_name)
        };

        let newtype_variant_handling = quote! {
            Ok(#name::#variant_name(access.newtype_variant()?))
        };

        let tuple_variant_handling = quote! {
            let (a,b) = access.tuple_variant(2, #tuple_visitor_name::new())?;
            Ok(#name::#variant_name(a, b))
        };

        // construct a match arm for the non-human-readable case based on the type
        let match_arm_non_self_describing = match &variant.fields {
            Fields::Unit => quote! {
                #storage_tag => { #unit_variant_handling },
            },
            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                quote! {
                    #storage_tag => { #newtype_variant_handling },
                }
            }
            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 2 => {
                quote! {
                    #storage_tag => { #tuple_variant_handling },
                }
            }
            _ => unimplemented!("fields not supported"),
        };
        match_arms_non_self_describing.push(match_arm_non_self_describing);

        // construct a match arm for the human-readable case based on the type
        let match_arm_self_describing = match &variant.fields {
            Fields::Unit => quote! {
                #variant_name_str => { #unit_variant_handling },
            },
            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                quote! {
                    #variant_name_str => { #newtype_variant_handling },
                }
            }
            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 2 => {
                quote! {
                    #variant_name_str => { #tuple_variant_handling },
                }
            }
            _ => unimplemented!("fields not supported"),
        };
        match_arms_self_describing.push(match_arm_self_describing);
    }

    quote! {

        impl <'de> serde::Deserialize<'de>  for #name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                const VARIANT_NAMES: &[&'static str] = &[#(#variant_names), *];
                if d.is_human_readable() {
                    d.deserialize_enum(
                        stringify!(#name),
                        VARIANT_NAMES,
                        #human_readable_visitor
                    )

                } else {
                    d.deserialize_enum(
                        stringify!(#name),
                        VARIANT_NAMES,
                        #non_human_readable_visitor
                    )
                }

            }
        }

        /// A visitor for self-describing enum deserialization
        struct #human_readable_visitor;

        impl <'de> serde::de::Visitor<'de> for #human_readable_visitor {
            type Value = #name;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!(#name))
            }

            fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<#name, A::Error> {
                use serde::de::VariantAccess;
                let (variant_str, access): (String, _) = data.variant()?;
                match variant_str.as_str() {
                    #(#match_arms_self_describing)*
                    _ => Err(serde::de::Error::custom(format!("unexpected variant name {}", variant_str))),
                }
            }

        }

        /// A visitor for non-self-describing enum serialization
        struct #non_human_readable_visitor;

        impl <'de> serde::de::Visitor<'de> for #non_human_readable_visitor {
            type Value = #name;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!(#name))
            }

            fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<#name, A::Error> {
                use serde::de::VariantAccess;
                let (storage_tag, access) = data.variant::<u32>()?;

                match storage_tag {
                    #(#match_arms_non_self_describing)*
                    _ => Err(serde::de::Error::custom(format!("unexpected storage tag {}", storage_tag))),
                }
            }

        }

        /// A visitor for deserializing the tuple contents of an enum variant
        struct #tuple_visitor_name<A, B>(std::marker::PhantomData<A>, std::marker::PhantomData<B>);

        impl<A, B> #tuple_visitor_name<A,B> {
            fn new() -> Self {
                Self(std::marker::PhantomData, std::marker::PhantomData)
            }
        }

        impl<'de, A: serde::de::Deserialize<'de>, B: serde::de::Deserialize<'de>> serde::de::Visitor<'de>
            for #tuple_visitor_name<A, B>
        {
            type Value = (A, B);

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a tuple of two elements")
            }

            // XXX: retrieve each tuple entry in the sequence
            fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut data: S) -> Result<Self::Value, S::Error> {
                let a: A = data.next_element()?
                    .ok_or_else(|| serde::de::Error::custom("missing tuple item"))?;
                let b: B = data.next_element()?
                    .ok_or_else(|| serde::de::Error::custom("missing tuple item"))?;
                Ok((a, b))
            }
        }


    }
}
