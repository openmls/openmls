use super::*;

use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};
#[derive(Serialize, Deserialize)]
pub struct SerializedManagedGroup {
    managed_group_config: ManagedGroupConfig,
    group: MlsGroup,
    pending_proposals: Vec<MlsPlaintext>,
    own_kpbs: Vec<KeyPackageBundle>,
    aad: Vec<u8>,
    resumption_secret_store: ResumptionSecretStore,
    active: bool,
}

impl SerializedManagedGroup {
    pub(crate) fn into_managed_group(mut self, callbacks: &ManagedGroupCallbacks) -> ManagedGroup {
        self.managed_group_config.set_callbacks(callbacks);
        ManagedGroup {
            managed_group_config: self.managed_group_config,
            group: self.group,
            pending_proposals: self.pending_proposals,
            own_kpbs: self.own_kpbs,
            aad: self.aad,
            resumption_secret_store: self.resumption_secret_store,
            active: self.active,
        }
    }
}

impl Serialize for ManagedGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SerializedManagedGroup", 6)?;
        state.serialize_field("managed_group_config", &self.managed_group_config)?;
        state.serialize_field("group", &self.group)?;
        state.serialize_field("pending_proposals", &self.pending_proposals)?;
        state.serialize_field("own_kpbs", &self.own_kpbs)?;
        state.serialize_field("aad", &self.aad)?;
        state.serialize_field("resumption_secret_store", &self.resumption_secret_store)?;
        state.serialize_field("active", &self.active)?;
        state.end()
    }
}
