use crate::component::{ComponentData, ComponentId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

#[derive(thiserror::Error, Debug)]
enum BuildAppDataDictionaryError {
    #[error("entries not in order")]
    EntriesNotInOrder,
    #[error("duplicate entries")]
    DuplicateEntries,
}

/// Serializable app data dictionary in the [`AppDataDictionaryExtension`].
///
/// This struct contains a list of [`ComponentData`] entries.
/// Entries are in order, and there is at most one entry per [`ComponentId`].
/// These properties are checked upon creation, as well as upon deserialization.
#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppDataDictionary {
    // NOTE: A BTreeMap is used here to ensure that the data is ordered by keys,
    // and unique. Since this also goes into the actual MLS Extension message, you could argue that
    // this should be a Vec<ComponentData>. However, inserting in the middle is much easier (and
    // cheaper) with the BTreeMap. The one thing that is a bit slower now is the `len` method,
    // which iterates over all keys.
    component_data: BTreeMap<ComponentId, ComponentData>,
}

impl AppDataDictionary {
    /// Initialize a new, empty [`AppDataDictionary`].
    pub fn new() -> Self {
        Self {
            component_data: BTreeMap::new(),
        }
    }
    /// Returns an iterator over the [`ComponentData`] entries,
    /// ordered by [`ComponentId`].
    pub fn entries(&self) -> impl Iterator<Item = &ComponentData> {
        self.component_data.values()
    }

    pub fn to_entries(self) -> Vec<ComponentData> {
        self.entries().cloned().collect()
    }

    /// Returns the number of entries in the dictionary.
    pub fn len(&self) -> usize {
        // NOTE: BTreeMap::len() is unstable, so BTreeMap::keys().count() is used instead.
        // This is O(n) instead of O(1) - easy to optimize if this is a bottleneck.
        self.component_data.keys().count()
    }

    /// Get a reference to an entry in the dictionary.
    pub fn get(&self, component_id: &ComponentId) -> Option<&[u8]> {
        self.component_data
            .get(component_id)
            .map(|component_data| component_data.data())
    }

    /// Insert an entry into the dictionary. If an entry for this [`ComponentId`] already exists,
    /// replace the old entry and return it.
    pub fn insert(&mut self, component_id: ComponentId, data: Vec<u8>) -> Option<VLBytes> {
        self.component_data
            .insert(
                component_id,
                ComponentData::from_parts(component_id, data.into()),
            )
            .map(|component_data| component_data.into_data())
    }

    /// Returns `true` if the dictionary contains an entry for the specified [`ComponentId`].
    pub fn contains(&self, component_id: &ComponentId) -> bool {
        self.component_data.contains_key(component_id)
    }

    /// Remove an entry from the dictionary by [`ComponentId`]. If this entry exists,
    /// return it.
    pub fn remove(&mut self, component_id: &ComponentId) -> Option<VLBytes> {
        self.component_data
            .remove(component_id)
            .map(|component_data| component_data.into_data())
    }

    /// Creates an [`AppDataDictionary`] from an `impl IntoIterator<Item = ComponentData>`.
    ///
    /// Ensures that the list is ordered by [`ComponentId`], and that there is at most one entry per [`ComponentId`].
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.6-5>
    fn try_from_data(
        data: impl IntoIterator<Item = ComponentData>,
    ) -> Result<Self, BuildAppDataDictionaryError> {
        let mut map = BTreeMap::<ComponentId, ComponentData>::new();

        for component_data in data {
            let (component_id, data) = component_data.into_parts();
            // Check for duplicates
            if map.contains_key(&component_id) {
                return Err(BuildAppDataDictionaryError::DuplicateEntries);
            }

            // Check the ordering
            // The component id must be greater than all previous component ids
            if let Some((max, _)) = map.last_key_value() {
                if *max > component_id {
                    return Err(BuildAppDataDictionaryError::EntriesNotInOrder);
                }
            }
            // Update the last component id
            let _ = map.insert(component_id, ComponentData::from_parts(component_id, data));
        }

        Ok(Self {
            component_data: map,
        })
    }
}

impl tls_codec::Size for AppDataDictionary {
    fn tls_serialized_len(&self) -> usize {
        // get length without copying
        let data: Vec<&ComponentData> = self.entries().collect();
        data.tls_serialized_len()
    }
}

impl tls_codec::Serialize for AppDataDictionary {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // serialize without copying
        let data: Vec<&ComponentData> = self.entries().collect();
        data.tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for AppDataDictionary {
    /// Deserialize from bytes.
    ///
    /// This function also ensures that the [`ComponentData`] entries are in order by
    /// [`ComponentId`], and there is at most one entry per [`ComponentId`].
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // First deserialize as vector of ComponentData
        let data = Vec::<ComponentData>::tls_deserialize(bytes)?;

        // Convert to an AppDataDictionary
        AppDataDictionary::try_from_data(data)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}

impl tls_codec::DeserializeBytes for AppDataDictionary {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error> {
        use tls_codec::{Deserialize, Size};
        let mut bytes_ref = bytes;
        let dictionary = Self::tls_deserialize(&mut bytes_ref)?;

        let remainder = &bytes[dictionary.tls_serialized_len()..];

        Ok((dictionary, remainder))
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
    Default,
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

#[cfg(test)]
mod test {
    use super::*;
    use tls_codec::{Deserialize, Serialize};

    #[openmls_test::openmls_test]
    fn test_serialize_deserialize() {
        // build a dictionary with one entry
        let mut dictionary = AppDataDictionary::new();
        let _ = dictionary.insert(0, vec![]);
        let _ = dictionary.insert(0, vec![1, 2, 3]);

        assert_eq!(dictionary.len(), 1);

        // build a dictionary with multiple entries
        let mut dictionary_orig = AppDataDictionary::new();
        let _ = dictionary_orig.insert(5, vec![]);
        let _ = dictionary_orig.insert(0, vec![1, 2, 3]);

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
        // build a dictionary with no entries
        let dictionary_orig = AppDataDictionary::new();

        assert_eq!(dictionary_orig.len(), 0);

        // create an extension from the dictionary
        let extension_orig = AppDataDictionaryExtension::new(dictionary_orig.clone());

        // test serialization and deserialization of constructed dictionary
        let bytes = extension_orig.tls_serialize_detached().unwrap();
        let extension_deserialized =
            AppDataDictionaryExtension::tls_deserialize(&mut bytes.as_slice()).unwrap();
        assert_eq!(extension_orig, extension_deserialized);
    }
    // TODO: replace with FrankenApppDataDictionary
    #[openmls_test::openmls_test]
    fn test_serialization_invalid() {
        // incorrect dictionary with repeat entries
        // serialize the raw content
        let component_data = vec![
            ComponentData::from_parts(5, vec![].into()),
            ComponentData::from_parts(5, vec![1, 2, 3].into()),
            ComponentData::from_parts(9, vec![].into()),
        ];

        let serialized = component_data.tls_serialize_detached().unwrap();
        let err = AppDataDictionary::tls_deserialize_exact(serialized).unwrap_err();
        assert_eq!(
            err,
            tls_codec::Error::DecodingError(
                BuildAppDataDictionaryError::DuplicateEntries.to_string()
            )
        );

        // incorrect dictionary with out-of-order entries
        // serialize the raw content
        let component_data = vec![
            ComponentData::from_parts(5, vec![].into()),
            ComponentData::from_parts(9, vec![].into()),
            ComponentData::from_parts(4, vec![1, 2, 3].into()),
        ];

        let serialized = component_data.tls_serialize_detached().unwrap();
        let err = AppDataDictionary::tls_deserialize_exact(serialized).unwrap_err();
        assert_eq!(
            err,
            tls_codec::Error::DecodingError(
                BuildAppDataDictionaryError::EntriesNotInOrder.to_string()
            )
        );
    }
}
