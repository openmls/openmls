use super::*;

use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};

/// Helper struct that contains the serializable values of an `MlsGroup.
#[deprecated(
    since = "0.4.1",
    note = "It is temporarily exposed, it will be private again after #245"
)]
#[derive(Serialize, Deserialize)]
pub struct SerializedMlsGroup {
    mls_group_config: MlsGroupConfig,
    group: CoreGroup,
    proposal_store: ProposalStore,
    own_kpbs: Vec<KeyPackageBundle>,
    aad: Vec<u8>,
    resumption_secret_store: ResumptionSecretStore,
    group_state: MlsGroupState,
}

impl SerializedMlsGroup {
    /// Helper method that converts the SerializedMlsGroup to MlsGroup.
    pub fn into_mls_group(self) -> MlsGroup {
        MlsGroup {
            mls_group_config: self.mls_group_config,
            group: self.group,
            proposal_store: self.proposal_store,
            own_kpbs: self.own_kpbs,
            aad: self.aad,
            resumption_secret_store: self.resumption_secret_store,
            group_state: self.group_state,
            state_changed: InnerState::Persisted,
        }
    }
}

impl Serialize for MlsGroup {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SerializedMlsGroup", 6)?;
        state.serialize_field("mls_group_config", &self.mls_group_config)?;
        state.serialize_field("group", &self.group)?;
        state.serialize_field("proposal_store", &self.proposal_store)?;
        state.serialize_field("own_kpbs", &self.own_kpbs)?;
        state.serialize_field("aad", &self.aad)?;
        state.serialize_field("resumption_secret_store", &self.resumption_secret_store)?;
        state.serialize_field("group_state", &self.group_state)?;
        state.end()
    }
}
