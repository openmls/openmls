//! Serialization helpers for enums.
//!
//! These helpers provide custom implementations of [`serde::Serialize`]
//! and [`serde::Deserialize`] for the provided enums.
//!
//! These affect non-self-describing serializations, ensuring that the storage tag
//! specified on each enum variant is used as the numeric tag for that variant
//! (instead of its position in the ordering of variants).
//!
//! **NOTE**: These storage tags are always written as `u32` values in the `serde`
//! non-self-describing serializations.
//!
//! ### Usage
//! Annotate an enum with the [`Serialize`] and [`Deserialize`] macros
//! to derive [`serde::Serialize`] and [`serde::Deserialize`] traits
//! automatically for these enums.
//! ```rust
//! #[derive(
//!     openmls_serialization_helpers::Serialize,
//!     openmls_serialization_helpers::Deserialize,
//! )]
//! pub enum TestEnum {
//!   #[storage_tag = 0]
//!   Unit,
//!   #[storage_tag = 2]
//!   Data(Vec<u8>),
//!   #[storage_tag = 4]
//!   Tuple(usize, Vec<u8>),
//! }
//! ```
//!
//! Other enum variant formats (such as `Data { field: .. }`) are not supported
//! by these macros.

mod attrs;
mod deserialize;
mod serialize;

use proc_macro::TokenStream;

#[proc_macro_derive(Deserialize, attributes(storage_tag))]
pub fn deserialize(input: TokenStream) -> TokenStream {
    deserialize::deserialize(input.into()).into()
}

#[proc_macro_derive(Serialize, attributes(storage_tag))]
pub fn serialize(input: TokenStream) -> TokenStream {
    serialize::serialize(input.into()).into()
}
