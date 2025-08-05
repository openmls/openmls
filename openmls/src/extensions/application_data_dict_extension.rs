use super::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

// TODO: use newtype or type alias defined elsewhere?
pub type ComponentId = u32;

/// TODO: doc comment
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

/// TODO: doc comment
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
pub struct AppDataDictionary {
    component_data: Vec<ComponentData>,
}

/// TODO: doc comment
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
pub struct ApplicationDataDictionaryExtension {
    dictionary: AppDataDictionary,
}
