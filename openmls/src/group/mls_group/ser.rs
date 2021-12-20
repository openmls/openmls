use super::*;

use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};
#[derive(Serialize, Deserialize)]
pub struct SerializedMlsGroup {
    mls_group_config: MlsGroupConfig,
    group: CoreGroup,
    proposal_store: ProposalStore,
    message_secrets_store: MessageSecretsStore,
    own_kpbs: Vec<KeyPackageBundle>,
    aad: Vec<u8>,
    resumption_secret_store: ResumptionSecretStore,
    active: bool,
}

impl SerializedMlsGroup {
    pub(crate) fn into_mls_group(self) -> MlsGroup {
        MlsGroup {
            mls_group_config: self.mls_group_config,
            group: self.group,
            proposal_store: self.proposal_store,
            message_secrets_store: self.message_secrets_store,
            own_kpbs: self.own_kpbs,
            aad: self.aad,
            resumption_secret_store: self.resumption_secret_store,
            active: self.active,
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
        state.serialize_field("message_secrets_store", &self.message_secrets_store)?;
        state.serialize_field("own_kpbs", &self.own_kpbs)?;
        state.serialize_field("aad", &self.aad)?;
        state.serialize_field("resumption_secret_store", &self.resumption_secret_store)?;
        state.serialize_field("active", &self.active)?;
        state.end()
    }
}
