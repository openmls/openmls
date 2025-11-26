//! Components from the extensions draft.

use tls_codec::{TlsSerialize, TlsSize, VLBytes};

/// A ComponentId that uniquely identifies a component within the scope of an application.
pub type ComponentId = u16;

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
