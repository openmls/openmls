use super::*;
use crate::component::ComponentId;

/// [`AppDataUpdateProposal`] operation types
#[repr(u8)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Serialize, Deserialize, Hash)]
pub enum AppDataUpdateOperationType {
    /// Update operation
    Update = 1,
    /// Remove operation
    Remove = 2,
}

#[repr(u8)]
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
/// The operation that is part of an [`AppDataUpdateProposal`].
pub enum AppDataUpdateOperation {
    /// Update operation, containing update data
    #[tls_codec(discriminant = 1)]
    Update(VLBytes) = 1,
    /// Remove operation
    #[tls_codec(discriminant = 2)]
    Remove = 2,
}

impl AppDataUpdateOperation {
    /// Returns the operation type.
    pub fn operation_type(&self) -> AppDataUpdateOperationType {
        match self {
            AppDataUpdateOperation::Update(_) => AppDataUpdateOperationType::Update,
            AppDataUpdateOperation::Remove => AppDataUpdateOperationType::Remove,
        }
    }
}

/// AppDataUpdate Proposal.
///
/// ```c
/// struct {
///     ComponentID component_id;
///     AppDataUpdateOperation op;
///
///     select (AppDataUpdate.op) {
///     case update: opaque update<V>;
///     case remove: struct{};
///     };
/// } AppDataUpdate;
/// ```
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
)]
pub struct AppDataUpdateProposal {
    component_id: ComponentId,
    operation: AppDataUpdateOperation,
}

impl AppDataUpdateProposal {
    /// Create a new AppDataUpdateProposal containing an Update operation.
    pub fn update(component_id: ComponentId, data: impl Into<VLBytes>) -> Self {
        Self::new(component_id, AppDataUpdateOperation::Update(data.into()))
    }
    /// Create a new AppDataUpdateProposal containing a Remove operation.
    pub fn remove(component_id: ComponentId) -> Self {
        Self::new(component_id, AppDataUpdateOperation::Remove)
    }
    pub(crate) fn new(component_id: ComponentId, operation: AppDataUpdateOperation) -> Self {
        Self {
            component_id,
            operation,
        }
    }

    /// Return the [`ComponentId`] for this proposal.
    pub fn component_id(&self) -> ComponentId {
        self.component_id
    }
    /// Return the [`AppDataUpdateOperation`] for this proposal.
    pub fn operation(&self) -> &AppDataUpdateOperation {
        &self.operation
    }
}
