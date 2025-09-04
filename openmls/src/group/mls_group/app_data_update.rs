use super::{staged_commit::StagedCommit, Extension, LibraryError};
use crate::{
    extensions::{AppDataDictionaryExtension, ComponentId, ExtensionType},
    messages::proposals::{
        AppDataUpdateOperation, AppDataUpdateOperationType, AppDataUpdateProposal,
    },
};
use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug)]
pub struct StagedCommitWithPendingAppDataUpdates(pub(crate) Box<StagedCommit>);

// TODO: are any other variants needed?
#[derive(Error, Debug, PartialEq, Eq, Clone)]
/// An error returned by the app logic when applying an AppDataUpdate proposal.
pub enum ApplyAppLogicError {
    #[error("The proposal is invalid.")]
    /// The proposal is invalid.
    Invalid,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ValidateAppDataUpdateError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("This ComponentId is not known to the application.")]
    /// This [`ComponentId`] is not known to the application.
    ComponentNotRegistered,
    #[error("The proposal was rejected by the registered application logic.")]
    /// The proposal was rejected by the registered application logic.
    RejectedByAppLogic,
    #[error(
        "Cannot apply application logic to an AppDataUpdate proposal of operation type Remove."
    )]
    /// Cannot apply application logic to an [`AppDataUpdateProposal`] of
    /// [`AppDataUpdateOperationType::Remove`].
    ProposalTypeIsRemove,
    #[error("A component with this ComponentId is not present in the AppDataDictionary.")]
    /// A component with this [`ComponentId`] is not present in the
    /// [`AppDataDictionary`](crate::extensions::AppDataDictionary).
    ComponentNotInDictionary,
    #[error("The GroupContext does not contain an AppDataDictionary extension.")]
    /// The [`GroupContext`] does not contain an [`AppDataDictionaryExtension`].
    NoAppDataDictionaryExtension,
}

type RegisteredComponentLogic = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, ApplyAppLogicError>>;

pub struct RegisteredComponentsWithLogic(BTreeMap<ComponentId, RegisteredComponentLogic>);

impl RegisteredComponentsWithLogic {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    /// Register a [`ComponentId`] alongside its application logic.
    pub fn register(
        &mut self,
        component_id: ComponentId,
        app_logic: impl Fn(&[u8]) -> Result<Vec<u8>, ApplyAppLogicError> + 'static,
    ) {
        let _ = self.0.insert(component_id, Box::new(app_logic));
    }
    pub fn contains(&self, component_id: ComponentId) -> bool {
        self.0.contains_key(&component_id)
    }

    pub fn apply_logic(
        &self,
        proposal: &AppDataUpdateProposal,
    ) -> Result<Vec<u8>, ValidateAppDataUpdateError> {
        let app_logic = self
            .0
            .get(&proposal.component_id())
            .ok_or(ValidateAppDataUpdateError::ComponentNotRegistered)?;

        // extract the update data
        let update = match proposal.operation() {
            AppDataUpdateOperation::Update(data) => data,
            AppDataUpdateOperation::Remove => {
                return Err(ValidateAppDataUpdateError::ProposalTypeIsRemove)
            }
        };

        // apply the app logic
        app_logic(update.as_ref()).map_err(|_| ValidateAppDataUpdateError::RejectedByAppLogic)
    }
}

impl StagedCommitWithPendingAppDataUpdates {
    pub fn apply_app_logic(
        mut self,
        registered_logic: &RegisteredComponentsWithLogic,
    ) -> Result<Box<StagedCommit>, ValidateAppDataUpdateError> {
        let updates = self
            .0
            .staged_proposal_queue
            .app_data_update_proposals()
            .map(|p| p.app_data_update_proposal);

        // Retrieve mutable reference to
        // the GroupContext extensions in the StagedDiff
        let extensions = self
            .0
            .state
            .staged_diff_mut()
            .group_context_mut()
            .extensions_mut();

        for update in updates {
            match update.operation().operation_type() {
                AppDataUpdateOperationType::Update => {
                    let new_data = registered_logic.apply_logic(update)?;
                    // In the extensions, initialize an empty AppDataDictionary
                    // if there is not already one present
                    if !extensions.contains(ExtensionType::AppDataDictionary) {
                        extensions
                            .add(Extension::AppDataDictionary(
                                AppDataDictionaryExtension::default(),
                            ))
                            .map_err(|_| {
                                LibraryError::custom("AppDataDictionary extension already exists")
                            })?;
                    }
                    // inserts an empty dictionary entry if not already exists
                    // retrieve the AppDataDictionary, to mutate the Extension in place
                    let dictionary = extensions
                        .app_data_dictionary_mut()
                        .ok_or_else(|| {
                            LibraryError::custom("AppDataDictionary should have been created")
                        })?
                        .dictionary_mut();
                    let _ = dictionary.insert(update.component_id(), new_data);
                }
                AppDataUpdateOperationType::Remove => {
                    if !registered_logic.contains(update.component_id()) {
                        return Err(ValidateAppDataUpdateError::ComponentNotRegistered);
                    }
                    // remove the entry if the dictionary exists
                    if let Some(dictionary_ext) = extensions.app_data_dictionary_mut() {
                        let dictionary = dictionary_ext.dictionary_mut();
                        if !dictionary.contains(&update.component_id()) {
                            return Err(ValidateAppDataUpdateError::ComponentNotInDictionary);
                        }
                        let _ = dictionary.remove(&update.component_id());
                    } else {
                        return Err(ValidateAppDataUpdateError::NoAppDataDictionaryExtension);
                    }
                }
            }
        }

        // return the staged commit
        Ok(self.0)
    }
}
