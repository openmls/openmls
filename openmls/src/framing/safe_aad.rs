//! Safe Additional Authenticated Data (Safe AAD) framing.
//!
//! Implements the wire format and validation rules from
//! <https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions> Section 4.9.
//!
//! ```tls
//! struct {
//!   ComponentID component_id;
//!   opaque aad_item_data<V>;
//! } SafeAADItem;
//!
//! struct {
//!   SafeAADItem aad_items<V>;
//! } SafeAAD;
//! ```
//!
//! Items in a [`SafeAad`] are sorted in strictly-increasing order of
//! `component_id`. Duplicates and misordering are rejected on both construction
//! and deserialization.

use serde::{Deserialize, Serialize};
use std::io::Read;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
    VLBytes,
};

use crate::component::ComponentId;

/// Errors that can occur when building or parsing a [`SafeAad`].
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum SafeAadError {
    /// Two items share the same [`ComponentId`].
    #[error("duplicate component id in SafeAAD: {0}")]
    DuplicateComponentId(ComponentId),
    /// Items are not sorted in strictly-increasing order by [`ComponentId`].
    #[error("SafeAAD items are not sorted by component id in increasing order")]
    ItemsNotSortedAscending,
    /// Encoding or decoding failure.
    #[error("codec error: {0}")]
    Codec(String),
}

/// A single Safe AAD entry tagged by [`ComponentId`].
///
/// ```tls
/// struct {
///   ComponentID component_id;
///   opaque aad_item_data<V>;
/// } SafeAADItem;
/// ```
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct SafeAadItem {
    component_id: ComponentId,
    aad_item_data: VLBytes,
}

impl SafeAadItem {
    /// Create a new [`SafeAadItem`].
    pub fn new(component_id: ComponentId, data: Vec<u8>) -> Self {
        Self {
            component_id,
            aad_item_data: data.into(),
        }
    }

    /// The [`ComponentId`] this item is tagged with.
    pub fn component_id(&self) -> ComponentId {
        self.component_id
    }

    /// The bytes carried by this item.
    pub fn data(&self) -> &[u8] {
        self.aad_item_data.as_slice()
    }
}

/// A Safe AAD struct as it appears at the beginning of an MLS message's
/// `authenticated_data` field when negotiated for the group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct SafeAad {
    aad_items: Vec<SafeAadItem>,
}

impl SafeAad {
    /// Build a [`SafeAad`] from a list of items.
    ///
    /// Returns an error if items are not sorted in strictly-increasing
    /// [`ComponentId`] order or if any [`ComponentId`] appears more than once.
    pub fn from_items(items: Vec<SafeAadItem>) -> Result<Self, SafeAadError> {
        Self::validate(&items)?;
        Ok(Self { aad_items: items })
    }

    /// Build an empty [`SafeAad`].
    pub fn empty() -> Self {
        Self {
            aad_items: Vec::new(),
        }
    }

    /// Returns all items.
    pub fn items(&self) -> &[SafeAadItem] {
        &self.aad_items
    }

    /// Look up the data carried for a given [`ComponentId`].
    ///
    /// Returns `None` if there is no item tagged with that id.
    pub fn get(&self, component_id: ComponentId) -> Option<&[u8]> {
        // The list is sorted by construction, so a binary search is correct
        // and cheap.
        self.aad_items
            .binary_search_by_key(&component_id, SafeAadItem::component_id)
            .ok()
            .map(|index| self.aad_items[index].data())
    }

    /// Returns true if there are no items.
    pub fn is_empty(&self) -> bool {
        self.aad_items.is_empty()
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.aad_items.len()
    }

    fn validate(items: &[SafeAadItem]) -> Result<(), SafeAadError> {
        let mut previous: Option<ComponentId> = None;
        for item in items {
            if let Some(prev) = previous {
                if item.component_id == prev {
                    return Err(SafeAadError::DuplicateComponentId(item.component_id));
                }
                if item.component_id < prev {
                    return Err(SafeAadError::ItemsNotSortedAscending);
                }
            }
            previous = Some(item.component_id);
        }
        Ok(())
    }
}

impl TlsDeserializeTrait for SafeAad {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let aad_items = Vec::<SafeAadItem>::tls_deserialize(bytes)?;
        SafeAad::from_items(aad_items)
            .map_err(|err| tls_codec::Error::DecodingError(err.to_string()))
    }
}

impl TlsDeserializeBytesTrait for SafeAad {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        let (aad_items, rest) = Vec::<SafeAadItem>::tls_deserialize_bytes(bytes)?;
        let aad = SafeAad::from_items(aad_items)
            .map_err(|err| tls_codec::Error::DecodingError(err.to_string()))?;
        Ok((aad, rest))
    }
}

/// Build the bytes that go into `authenticated_data` for an outgoing message
/// when Safe AAD is required: the TLS-serialized [`SafeAad`] followed by the
/// caller-supplied tail bytes.
pub(crate) fn assemble_authenticated_data(
    safe_aad: &SafeAad,
    tail: &[u8],
) -> Result<Vec<u8>, SafeAadError> {
    let mut out = safe_aad
        .tls_serialize_detached()
        .map_err(|err| SafeAadError::Codec(err.to_string()))?;
    out.extend_from_slice(tail);
    Ok(out)
}

/// Parse the [`SafeAad`] prefix from `authenticated_data` bytes when Safe AAD
/// is required for the group. Returns the parsed struct and the length of the
/// consumed prefix.
pub(crate) fn parse_authenticated_data_prefix(
    bytes: &[u8],
) -> Result<(SafeAad, usize), SafeAadError> {
    let (parsed, remainder) = SafeAad::tls_deserialize_bytes(bytes)
        .map_err(|err| SafeAadError::Codec(err.to_string()))?;
    let prefix_len = bytes.len() - remainder.len();
    Ok((parsed, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::{Deserialize, Serialize};

    fn item(id: ComponentId, data: &[u8]) -> SafeAadItem {
        SafeAadItem::new(id, data.to_vec())
    }

    #[test]
    fn roundtrip_non_empty() {
        let safe_aad = SafeAad::from_items(vec![
            item(1, b"first"),
            item(7, b""),
            item(42, b"last item bytes"),
        ])
        .unwrap();

        let bytes = safe_aad.tls_serialize_detached().unwrap();
        let parsed = SafeAad::tls_deserialize_exact(&bytes).unwrap();

        assert_eq!(parsed, safe_aad);
        let reserialized = parsed.tls_serialize_detached().unwrap();
        assert_eq!(reserialized, bytes);
    }

    #[test]
    fn empty_is_length_prefix_only() {
        let safe_aad = SafeAad::empty();
        let bytes = safe_aad.tls_serialize_detached().unwrap();

        // The TLS encoding of a zero-length `<V>` vector is a single zero byte.
        assert_eq!(bytes, vec![0x00]);

        let parsed = SafeAad::tls_deserialize_exact(&bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn from_items_rejects_duplicates() {
        let err = SafeAad::from_items(vec![item(3, b"a"), item(3, b"b")]).unwrap_err();
        assert_eq!(err, SafeAadError::DuplicateComponentId(3));
    }

    #[test]
    fn from_items_rejects_misordered() {
        let err = SafeAad::from_items(vec![item(9, b""), item(2, b"")]).unwrap_err();
        assert_eq!(err, SafeAadError::ItemsNotSortedAscending);
    }

    #[test]
    fn deserialize_rejects_misordered() {
        // Hand-craft TLS bytes for two items that are out of order. The derived
        // serializer would normally refuse to emit these, so we build the bytes
        // directly from items wrapped in a plain `Vec`.
        let raw_items: Vec<SafeAadItem> = vec![item(5, b"x"), item(1, b"y")];
        let raw_bytes = raw_items.tls_serialize_detached().unwrap();

        let err = SafeAad::tls_deserialize_exact(&raw_bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(message) => {
                assert!(
                    message.contains("not sorted"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_duplicates() {
        let raw_items: Vec<SafeAadItem> = vec![item(4, b""), item(4, b"")];
        let raw_bytes = raw_items.tls_serialize_detached().unwrap();

        let err = SafeAad::tls_deserialize_exact(&raw_bytes).unwrap_err();
        match err {
            tls_codec::Error::DecodingError(message) => {
                assert!(
                    message.contains("duplicate"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn boundary_component_ids() {
        let safe_aad = SafeAad::from_items(vec![item(0, b"min"), item(u16::MAX, b"max")]).unwrap();

        let bytes = safe_aad.tls_serialize_detached().unwrap();
        let parsed = SafeAad::tls_deserialize_exact(&bytes).unwrap();

        assert_eq!(parsed.get(0), Some(b"min".as_slice()));
        assert_eq!(parsed.get(u16::MAX), Some(b"max".as_slice()));
    }

    #[test]
    fn get_returns_none_for_missing() {
        let safe_aad = SafeAad::from_items(vec![item(1, b"a"), item(10, b"b")]).unwrap();
        assert_eq!(safe_aad.get(5), None);
        assert_eq!(safe_aad.get(1), Some(b"a".as_slice()));
        assert_eq!(safe_aad.get(10), Some(b"b".as_slice()));
    }

    #[test]
    fn assemble_and_parse_authenticated_data_roundtrip() {
        let safe_aad =
            SafeAad::from_items(vec![item(2, b"safe-aad-data"), item(8, b"more")]).unwrap();
        let tail = b"caller tail bytes";

        let combined = assemble_authenticated_data(&safe_aad, tail).unwrap();

        let (parsed, prefix_len) = parse_authenticated_data_prefix(&combined).unwrap();
        assert_eq!(parsed, safe_aad);
        assert_eq!(&combined[prefix_len..], tail);
    }
}
