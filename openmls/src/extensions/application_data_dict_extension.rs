use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

/// The unique ComponentId.
pub type ComponentId = u32;

/// An entry in the [`AppDataDictionary`].
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ComponentData {
    component_id: ComponentId,
    data: VLBytes,
}

impl ComponentData {
    /// Return the [`ComponentId`] for this entry.
    pub fn id(&self) -> ComponentId {
        self.component_id
    }

    /// Return the data as a byte slice.
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// Build an AppDataDictionary from a [`BTreeMap`].
impl<Data: Into<VLBytes>> From<BTreeMap<ComponentId, Data>> for AppDataDictionary {
    fn from(map: BTreeMap<ComponentId, Data>) -> Self {
        let component_data = map
            .into_iter()
            .map(|(component_id, data)| ComponentData {
                component_id,
                data: data.into(),
            })
            .collect();

        Self { component_data }
    }
}

/// App data dictionary in the [`AppDataDictionaryExtension`].
///
/// This struct contains a list of [`ComponentData`] entries.
/// Entries are in order, and there is at most one entry per [`ComponentId`].
/// These properties are checked upon creation, as well as upon deserialization.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    tls_codec::TlsSize,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserializeBytes,
)]
pub struct AppDataDictionary {
    component_data: Vec<ComponentData>,
}

// TODO: rename
#[derive(thiserror::Error, Debug)]
enum AppDataDictionaryError {
    #[error("entries not in order")]
    EntriesNotInOrder,
    #[error("duplicate entries")]
    DuplicateEntries,
}

impl AppDataDictionary {
    /// Returns a builder for this type.
    pub fn builder() -> AppDataDictionaryBuilder {
        AppDataDictionaryBuilder::new()
    }

    /// Consumes the dictionary and returns an iterator of the [`ComponentData`] entries,
    /// ordered by [`ComponentId`].
    pub fn entries(&self) -> impl Iterator<Item = &ComponentData> {
        self.component_data.iter()
    }

    /// Returns the number of elements in the dictionary.
    pub const fn len(&self) -> usize {
        self.component_data.len()
    }

    /// Returns `true` if the dictionary contains no elements.
    pub const fn is_empty(&self) -> bool {
        self.component_data.is_empty()
    }

    // TODO: Should this be added to the public API?
    /// Creates an [`AppDataDictionary`] from a Vec of [`ComponentData`] entries.
    ///
    /// Ensures that the list is ordered by [`ComponentId`], and that there is at most one entry per [`ComponentId`].
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.6-5>
    fn try_from_vec(data: Vec<ComponentData>) -> Result<Self, AppDataDictionaryError> {
        // Use an ordered set of processed ComponentIds to check conditions
        let mut seen = std::collections::BTreeSet::<ComponentId>::new();

        for ComponentData { component_id, .. } in data.iter() {
            // Check for duplicates
            if seen.contains(component_id) {
                return Err(AppDataDictionaryError::DuplicateEntries);
            }

            // Check the ordering
            // The component id must be greater than all previous component ids
            if let Some(max) = seen.last() {
                if max > component_id {
                    return Err(AppDataDictionaryError::EntriesNotInOrder);
                }
            }
            // Update the map
            seen.insert(*component_id);
        }

        Ok(Self {
            component_data: data,
        })
    }
}

impl tls_codec::Deserialize for AppDataDictionary {
    /// Deserialize from bytes.
    ///
    /// This function also ensures that the [`ComponentData`] entries are in order by
    /// [`ComponentId`], and there is at most one entry per [`ComponentId`].
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let vec = Vec::<ComponentData>::tls_deserialize(bytes)?;

        // Check that the required conditions hold
        AppDataDictionary::try_from_vec(vec)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}

/// App Data Dictionary Extension.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.6-3>
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct AppDataDictionaryExtension {
    dictionary: AppDataDictionary,
}

impl AppDataDictionaryExtension {
    /// Return the [`AppDataDictionary`] from this extension.
    pub fn dictionary(&self) -> &AppDataDictionary {
        &self.dictionary
    }
    /// Build a new extension from an [`AppDataDictionary`].
    pub fn new(dictionary: AppDataDictionary) -> Self {
        Self { dictionary }
    }
}

/// Builder struct for an [`AppDataDictionary`].
pub struct AppDataDictionaryBuilder {
    component_data: BTreeMap<ComponentId, VLBytes>,
}

use std::collections::BTreeMap;
impl AppDataDictionaryBuilder {
    fn new() -> Self {
        Self {
            component_data: BTreeMap::new(),
        }
    }

    /// Inserts an entry into the dictionary. Overwrites any existing entry with that [`ComponentId`].
    pub fn with_entry(mut self, id: ComponentId, data: &[u8]) -> Self {
        let _ = self.component_data.insert(id, data.into());

        self
    }

    /// Builds an [`AppDataDictionary`].
    pub fn build(self) -> AppDataDictionary {
        self.component_data.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tls_codec::{Deserialize, Serialize};

    #[openmls_test::openmls_test]
    fn test_serialize_deserialize() {
        // build a dictionary with one entry
        let dictionary = AppDataDictionary::builder()
            .with_entry(0, &[])
            // overwrites the last entry
            .with_entry(0, &[1, 2, 3])
            .build();

        assert_eq!(dictionary.len(), 1);

        // build a dictionary with multiple entries
        let dictionary_orig = AppDataDictionary::builder()
            .with_entry(5, &[])
            .with_entry(0, &[1, 2, 3])
            .build();

        assert_eq!(dictionary_orig.len(), 2);

        // create an extension from the dictionary
        let extension_orig = AppDataDictionaryExtension::new(dictionary_orig.clone());

        // test serialization and deserialization of constructed dictionary
        let bytes = extension_orig.tls_serialize_detached().unwrap();
        let extension_deserialized =
            AppDataDictionaryExtension::tls_deserialize(&mut bytes.as_slice()).unwrap();
        assert_eq!(extension_orig, extension_deserialized);
    }
    #[openmls_test::openmls_test]
    fn test_serialization_empty() {
        // build a dictionary with one entry
        let dictionary_orig = AppDataDictionary::builder().build();

        assert_eq!(dictionary_orig.len(), 0);

        // create an extension from the dictionary
        let extension_orig = AppDataDictionaryExtension::new(dictionary_orig.clone());

        // test serialization and deserialization of constructed dictionary
        let bytes = extension_orig.tls_serialize_detached().unwrap();
        let extension_deserialized =
            AppDataDictionaryExtension::tls_deserialize(&mut bytes.as_slice()).unwrap();
        assert_eq!(extension_orig, extension_deserialized);
    }
    #[openmls_test::openmls_test]
    fn test_serialization_invalid() {
        // incorrect dictionary with repeat entries
        let dictionary_orig = AppDataDictionary {
            component_data: vec![
                ComponentData {
                    component_id: 5,
                    data: vec![].into(),
                },
                ComponentData {
                    component_id: 9,
                    data: vec![].into(),
                },
                ComponentData {
                    component_id: 5,
                    data: vec![1, 2, 3].into(),
                },
            ],
        };

        let serialized = dictionary_orig.tls_serialize_detached().unwrap();
        let err = AppDataDictionary::tls_deserialize_exact(serialized).unwrap_err();
        assert_eq!(
            err,
            tls_codec::Error::DecodingError(AppDataDictionaryError::DuplicateEntries.to_string())
        );

        // incorrect dictionary with out-of-order entries
        let dictionary_orig = AppDataDictionary {
            component_data: vec![
                ComponentData {
                    component_id: 5,
                    data: vec![].into(),
                },
                ComponentData {
                    component_id: 9,
                    data: vec![].into(),
                },
                ComponentData {
                    component_id: 4,
                    data: vec![1, 2, 3].into(),
                },
            ],
        };

        let serialized = dictionary_orig.tls_serialize_detached().unwrap();
        let err = AppDataDictionary::tls_deserialize_exact(serialized).unwrap_err();
        assert_eq!(
            err,
            tls_codec::Error::DecodingError(AppDataDictionaryError::EntriesNotInOrder.to_string())
        );
    }
}
