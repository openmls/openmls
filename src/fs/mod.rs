//! # File System & Persistence
//!
//! This module implements persistence for MLS state.
//!

// TODO: Also persist managed groups instead of MLSGroups when #79 is done.

use crate::{
    config::Config,
    creds::Credential,
    group::{GroupId, MlsGroup},
    key_packages::KeyPackageBundle,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Error, Write},
    path::Path,
};

/// The global state struct that is persisted to disk and can be loaded again.
#[derive(Serialize, Deserialize)]
struct State {
    config: Config,
    groups: Vec<MlsGroup>,
    key_package_bundles: Vec<KeyPackageBundle>,
    credentials: Vec<Credential>,
    identities: Vec<Vec<u8>>,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        let mut result = self.config == other.config;
        let my_group_ids = self
            .groups
            .iter()
            .map(|g| g.group_id().clone())
            .collect::<Vec<GroupId>>();
        let other_group_ids = other
            .groups
            .iter()
            .map(|g| g.group_id().clone())
            .collect::<Vec<GroupId>>();
        result &= my_group_ids == other_group_ids;
        // TODO: compare all.
        result
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("config", &self.config)
            .field(
                "groups",
                &self
                    .groups
                    .iter()
                    .map(|g| g.group_id().clone())
                    .collect::<Vec<GroupId>>(),
            ) // TODO: add all...
            .finish()
    }
}

impl State {
    pub fn new(
        config: &'static Config,
        groups: Vec<MlsGroup>,
        key_package_bundles: Vec<KeyPackageBundle>,
        credentials: Vec<Credential>,
        identities: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            config: (*config).clone(),
            groups,
            key_package_bundles,
            credentials,
            identities,
        }
    }

    pub fn read(file: &Path) -> Result<Self, Error> {
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        let state: Self = serde_json::from_reader(reader)?;
        Ok(state)
    }

    pub fn write(&self, file: &Path) -> Result<(), Error> {
        let mut file = File::create(file)?;
        let state_out = serde_json::to_string_pretty(self)?;
        file.write_all(&state_out.into_bytes())
    }
}

#[test]
fn test_persistence() {
    let groups = Vec::new();
    let key_package_bundles = Vec::new();
    let credentials = Vec::new();
    let identities = Vec::new();

    let state = State::new(
        Config::_get(),
        groups,
        key_package_bundles,
        credentials,
        identities,
    );

    let state_file = Path::new("test_state.json");
    state.write(&state_file).unwrap();

    let new_state = State::read(&state_file).unwrap();
    assert_eq!(state, new_state);
}
