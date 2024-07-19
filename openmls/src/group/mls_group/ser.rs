// TODO #245: Remove this once we have a proper serialization format
#![allow(deprecated)]

use super::*;
use crate::schedule::psk::store::ResumptionPskStore;

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
    mls_group_config: MlsGroupJoinConfig,
    group: CoreGroup,
    own_leaf_nodes: Vec<LeafNode>,
    resumption_psk_store: ResumptionPskStore,
    group_state: MlsGroupState,
}

#[allow(clippy::from_over_into)]
impl Into<MlsGroup> for SerializedMlsGroup {
    fn into(self) -> MlsGroup {
        MlsGroup {
            mls_group_config: self.mls_group_config,
            group: self.group,
            own_leaf_nodes: self.own_leaf_nodes,
            aad: Vec::new(),
            group_state: self.group_state,
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
        state.serialize_field("own_leaf_nodes", &self.own_leaf_nodes)?;
        state.serialize_field("resumption_psk_store", &self.group.resumption_psk_store)?;
        state.serialize_field("group_state", &self.group_state)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MlsGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sgroup = SerializedMlsGroup::deserialize(deserializer)?;
        Ok(sgroup.into())
    }
}
