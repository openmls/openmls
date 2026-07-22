use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, Data, DeriveInput, Fields, FieldsUnnamed, Ident};

use crate::attrs::extract_storage_tag;

fn build_name_ident(name: &Ident, suffix: &str) -> Ident {
    Ident::new(&format!("{name}{suffix}"), name.span())
}

pub(crate) fn deserialize(input: TokenStream) -> TokenStream {
    // parse the input
    let input: DeriveInput = parse2(input).expect("error parsing token stream");
    let name = &input.ident;

    // retrieve the enum
    let Data::Enum(data_enum) = &input.data else {
        panic!("only enums are supported");
    };

    // keep track of whether the tuple visitor is needed to deserialize any of the variants
    let mut needs_tuple_visitor = false;

    // hashset of used storage tags to avoid collisions
    let mut storage_tags = std::collections::HashSet::new();

    // construct names for the generated visitor and variant-identifier helpers
    let enum_visitor = build_name_ident(name, "Visitor");
    let variant_id = build_name_ident(name, "VariantId");
    let variant_id_visitor = build_name_ident(name, "VariantIdVisitor");
    let tuple_visitor = build_name_ident(name, "TupleVisitor");

    let mut variant_names = vec![];
    let mut match_arms_non_self_describing = vec![];
    let mut match_arms_self_describing = vec![];
    for variant in data_enum.variants.iter() {
        // retrieve the variant name
        let variant_name = &variant.ident;
        let variant_name_str = variant_name.to_string();
        variant_names.push(variant_name_str.clone());

        // get the storage tag
        let storage_tag = extract_storage_tag(variant.attrs.iter()).unwrap_or_else(|e| {
            panic!("storage tag not provided for variant {name}::{variant_name}: {e}")
        });

        // check for duplicates
        if !storage_tags.insert(storage_tag) {
            panic!("Duplicate storage tags");
        }

        // construct a match arm for the non-human-readable case based on the type
        let handling = match &variant.fields {
            Fields::Unit => quote! {
                access.unit_variant()?;
                Ok(#name::#variant_name)
            },

            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 1 => {
                quote! {
                    Ok(#name::#variant_name(access.newtype_variant()?))
                }
            }
            Fields::Unnamed(FieldsUnnamed { unnamed, .. }) if unnamed.len() == 2 => {
                needs_tuple_visitor = true;
                quote! {
                    let (a,b) = access.tuple_variant(2, #tuple_visitor::new())?;
                    Ok(#name::#variant_name(a, b))
                }
            }
            _ => unimplemented!("fields not supported"),
        };
        match_arms_non_self_describing.push(quote! { #storage_tag => { #handling }, });
        match_arms_self_describing.push(quote! { #variant_name_str => { #handling }, });
    }

    let tuple_visitor_impl = if needs_tuple_visitor {
        quote! {
        /// A visitor for deserializing the tuple (A,B) contents of an enum variant
        struct #tuple_visitor<A, B>(std::marker::PhantomData<(A,B)>);

        impl<A, B> #tuple_visitor<A,B> {
            fn new() -> Self {
                Self(std::marker::PhantomData)
            }
        }

        impl<'de, A: serde::de::Deserialize<'de>, B: serde::de::Deserialize<'de>> serde::de::Visitor<'de>
            for #tuple_visitor<A, B>
        {
            type Value = (A, B);

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a tuple of two elements")
            }

            fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut data: S) -> Result<Self::Value, S::Error> {
                let a: A = data.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let b: B = data.next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok((a, b))
            }
        }
        }
    } else {
        quote! {}
    };

    let variant_id_visitor_impl = quote! {
        /// A variant identifier that accepts *either* the numeric storage tag or
        /// the variant name.
        enum #variant_id {
            Tag(u32),
            Name(String),
        }

        /// A visitor for variant identifier deserialization that supports
        /// both integer and string tags
        struct #variant_id_visitor;

        impl <'de> serde::de::Visitor<'de> for #variant_id_visitor {
            type Value = #variant_id;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("variant storage tag or name")
            }

            // NOTE: only tags that can be converted to a valid `u32` are accepted
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                u32::try_from(v).map(#variant_id::Tag).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Unsigned(v),
                        &"a variant storage tag that fits in a u32",
                    )
                })
            }

            fn visit_u32<E: serde::de::Error>(self, v: u32) -> Result<Self::Value, E> {
                Ok(#variant_id::Tag(v))
            }

            // NOTE: only tags that can be converted to a valid `u32` are accepted
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u32::try_from(v).map(#variant_id::Tag).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Signed(v),
                        &"a variant storage tag that fits in a u32",
                    )
                })
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(#variant_id::Name(v.to_string()))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                core::str::from_utf8(v)
                    .map(|s| #variant_id::Name(s.to_string()))
                    .map_err(|_| serde::de::Error::custom("invalid utf-8 in variant name"))
            }
        }

        impl <'de> serde::Deserialize<'de> for #variant_id {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_identifier(#variant_id_visitor)
            }
        }

    };

    quote! {

        impl <'de> serde::Deserialize<'de>  for #name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                const VARIANT_NAMES: &[&'static str] = &[#(#variant_names), *];
                d.deserialize_enum(stringify!(#name), VARIANT_NAMES, #enum_visitor)
            }
        }


        /// A visitor for enum deserialization, codec-agnostic (see #variant_id).
        struct #enum_visitor;

        impl <'de> serde::de::Visitor<'de> for #enum_visitor {
            type Value = #name;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(stringify!(#name))
            }

            fn visit_enum<A: serde::de::EnumAccess<'de>>(self, data: A) -> Result<#name, A::Error> {
                use serde::de::VariantAccess;
                // deserialize the variant id first
                let (variant_id, access) = data.variant::<#variant_id>()?;

                // deserialize differently depending on whether the variant id was an
                // integer tag or a string
                match variant_id {
                    #variant_id::Tag(storage_tag) => match storage_tag {
                        #(#match_arms_non_self_describing)*
                        _ => Err(serde::de::Error::custom(format!("unexpected storage tag {}", storage_tag))),
                    },
                    #variant_id::Name(variant_str) => match variant_str.as_str() {
                        #(#match_arms_self_describing)*
                        _ => Err(serde::de::Error::custom(format!("unexpected variant name \"{}\"", variant_str))),
                    },
                }
            }

        }

        #variant_id_visitor_impl

        #tuple_visitor_impl

    }
}
