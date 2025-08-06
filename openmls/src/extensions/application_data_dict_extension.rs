use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

// TODO: use newtype or type alias defined elsewhere?
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
    /// Returns an [`AppDataDictionaryBuilder`].
    pub fn builder() -> AppDataDictionaryBuilder {
        AppDataDictionaryBuilder::new()
    }

    // TODO: Should the Vec<ComponentData> be returned here?
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
    // <https://datatracker.ietf.org/doc/html/draft-ietf-mls-extensions#section-4.6-5>
    fn try_from_vec(data: Vec<ComponentData>) -> Result<Self, AppDataDictionaryError> {
        // Use an ordered map of processed ComponentIds to check conditions
        // See
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
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let vec = Vec::<ComponentData>::tls_deserialize(bytes)?;

        // Check that the required conditions hold
        AppDataDictionary::try_from_vec(vec)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}

// TODO: add link to extensions draft
/// App Data Dictionary Extension.
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
