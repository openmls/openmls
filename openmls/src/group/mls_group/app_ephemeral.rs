use super::staged_commit::StagedCommitState;

use crate::extensions::AppDataDictionaryExtension;

impl StagedCommitState {
    /// Return a mutable reference to the [`AppDataDictionaryExtension`], if it exists
    pub fn app_data_dictionary_mut(&mut self) -> Option<&mut AppDataDictionaryExtension> {
        self.group_context_mut()
            .extensions_mut()
            .app_data_dictionary_mut()
    }
}
