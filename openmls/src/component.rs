//! Components from the extensions draft.

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

/// A ComponentId that uniquely identifies a component within the scope of an application.
pub type ComponentId = u16;

/// An entry in the [`AppDataDictionary`].
///
/// [`AppDataDictionary`]: crate::extensions::AppDataDictionary
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
    pub fn into_data(self) -> VLBytes {
        self.data
    }

    /// Return the data as a byte slice.
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Consumes the struct and returns its component parts.
    pub fn into_parts(self) -> (ComponentId, VLBytes) {
        (self.component_id, self.data)
    }

    /// Create a new ComponentData from parts.
    pub fn from_parts(component_id: ComponentId, data: VLBytes) -> Self {
        Self { component_id, data }
    }
}

/// An unknown component id in the standardized range (0x0000-0x7fff)
#[repr(transparent)]
pub struct UnknownComponentId(u16);

impl UnknownComponentId {
    /// Creates a new [`UnknownComponentId`]. Only returns [`Some`] if it is not covered by any of the
    /// specified ranges.
    pub fn new(id: u16) -> Option<Self> {
        let is_grease = (id & 0x0f0f == 0x0a0a) && (id & 0xff == (id >> 8)) && id != 0xfefe;
        (!is_grease && matches!(id, ..0x8000)).then_some(Self(id))
    }
}

/// A component id from the private range (0x8000-0xffff)
#[repr(transparent)]
pub struct PrivateComponentId(u16);

impl PrivateComponentId {
    /// Creates a new [`PrivateComponentId`]. Only returns [`Some`] if it is in the range specified
    /// for private components (`0x8000..=0xffff`)
    /// specified ranges.
    pub fn new(id: u16) -> Option<Self> {
        matches!(id, 0x8000..).then_some(Self(id))
    }
}

#[cfg(feature = "extensions-draft-08")]
#[repr(u16)]
/// The type of a Component ID
pub enum ComponentType {
    /// ComponentId 0 is reserved
    Reserved = 0,
    /// The AppComponents component.
    AppComponents = 1,
    /// The SafeAad component.
    SafeAad = 2,
    /// The ComponentMediaTypes component.
    ComponentMediaTypes = 3,
    /// The LastResortKeyPackage component.
    LastResortKeyPackage = 4,
    /// The AppAck component.
    AppAck = 5,
    /// The GREASE component with ID 0x0A0A.
    Grease0A0A = 0x0a0a,
    /// The GREASE component with ID 0x1A1A.
    Grease1A1A = 0x1a1a,
    /// The GREASE component with ID 0x2A2A.
    Grease2A2A = 0x2a2a,
    /// The GREASE component with ID 0x3A3A.
    Grease3A3A = 0x3a3a,
    /// The GREASE component with ID 0x4A4A.
    Grease4A4A = 0x4a4a,
    /// The GREASE component with ID 0x5A5A.
    Grease5A5A = 0x5a5a,
    /// The GREASE component with ID 0x6A6A.
    Grease6A6A = 0x6a6a,
    /// The GREASE component with ID 0x7A7A.
    Grease7A7A = 0x7a7a,
    /// The GREASE component with ID 0x8A8A.
    Grease8A8A = 0x8a8a,
    /// The GREASE component with ID 0x9A9A.
    Grease9A9A = 0x9a9a,
    /// The GREASE component with ID 0xAAAA.
    GreaseAAAA = 0xaaaa,
    /// The GREASE component with ID 0xBABA.
    GreaseBABA = 0xbaba,
    /// The GREASE component with ID 0xCACA.
    GreaseCACA = 0xcaca,
    /// The GREASE component with ID 0xDADA.
    GreaseDADA = 0xdada,
    /// The GREASE component with ID 0xEAEA.
    GreaseEAEA = 0xeaea,

    /// An unknown component id in the standardized range (0x0000-0x7fff)
    Unknown(UnknownComponentId),

    /// A component id from the private range (0x8000-0xffff)
    Private(PrivateComponentId),
}

impl From<ComponentId> for ComponentType {
    fn from(value: ComponentId) -> Self {
        // We allow this here because we use the overlapping one at the bottom (..0x8000) as a catch-all.
        // This would be annoying to do explicitly because of the sparse GREASE values.
        #[allow(clippy::match_overlapping_arm)]
        match value {
            0 => Self::Reserved,
            1 => Self::AppComponents,
            2 => Self::SafeAad,
            3 => Self::ComponentMediaTypes,
            4 => Self::LastResortKeyPackage,
            5 => Self::AppAck,

            0x0a0a => Self::Grease0A0A,
            0x1a1a => Self::Grease1A1A,
            0x2a2a => Self::Grease2A2A,
            0x3a3a => Self::Grease3A3A,
            0x4a4a => Self::Grease4A4A,
            0x5a5a => Self::Grease5A5A,
            0x6a6a => Self::Grease6A6A,
            0x7a7a => Self::Grease7A7A,
            0x8a8a => Self::Grease8A8A,
            0x9a9a => Self::Grease9A9A,
            0xaaaa => Self::GreaseAAAA,
            0xbaba => Self::GreaseBABA,
            0xcaca => Self::GreaseCACA,
            0xdada => Self::GreaseDADA,
            0xeaea => Self::GreaseEAEA,

            6..0x8000 => Self::Unknown(UnknownComponentId(value)),
            0x8000.. => Self::Private(PrivateComponentId(value)),
        }
    }
}

impl From<ComponentType> for ComponentId {
    fn from(value: ComponentType) -> Self {
        match value {
            ComponentType::Reserved => 0,
            ComponentType::AppComponents => 1,
            ComponentType::SafeAad => 2,
            ComponentType::ComponentMediaTypes => 3,
            ComponentType::LastResortKeyPackage => 4,
            ComponentType::AppAck => 5,

            ComponentType::Grease0A0A => 0x0a0a,
            ComponentType::Grease1A1A => 0x1a1a,
            ComponentType::Grease2A2A => 0x2a2a,
            ComponentType::Grease3A3A => 0x3a3a,
            ComponentType::Grease4A4A => 0x4a4a,
            ComponentType::Grease5A5A => 0x5a5a,
            ComponentType::Grease6A6A => 0x6a6a,
            ComponentType::Grease7A7A => 0x7a7a,
            ComponentType::Grease8A8A => 0x8a8a,
            ComponentType::Grease9A9A => 0x9a9a,
            ComponentType::GreaseAAAA => 0xaaaa,
            ComponentType::GreaseBABA => 0xbaba,
            ComponentType::GreaseCACA => 0xcaca,
            ComponentType::GreaseDADA => 0xdada,
            ComponentType::GreaseEAEA => 0xeaea,

            ComponentType::Unknown(UnknownComponentId(id)) => id,
            ComponentType::Private(PrivateComponentId(id)) => id,
        }
    }
}

/// Label for safe encryption/decryption as defined in Section 4.2 of the MLS Extensions draft
#[derive(Debug, TlsSerialize, TlsSize)]
pub(crate) struct ComponentOperationLabel {
    /// "Application"
    base_label: VLBytes,
    component_id: ComponentId,
    label: VLBytes,
}

const COMPONENT_OPERATION_BASE_LABEL: &[u8] = b"Application";

impl ComponentOperationLabel {
    /// Creates a new ComponentOperationLabel, prefixed with "Application"
    pub fn new(component_id: ComponentId, label: &str) -> Self {
        Self {
            base_label: COMPONENT_OPERATION_BASE_LABEL.into(),
            component_id,
            label: label.as_bytes().into(),
        }
    }
}
