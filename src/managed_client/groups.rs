use crate::group::GroupId;
use crate::group::ManagedGroup;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use super::ManagedClientError;

#[derive(Default)]
pub(crate) struct Groups {
    group_states: RwLock<HashMap<GroupId, ManagedGroup>>,
}

pub struct MGReadGuard<'a> {
    gs: RwLockReadGuard<'a, HashMap<GroupId, ManagedGroup>>,
    index: &'a GroupId,
}

pub struct MGWriteGuard<'a> {
    gs: RwLockWriteGuard<'a, HashMap<GroupId, ManagedGroup>>,
    index: &'a GroupId,
}

impl<'b> Deref for MGWriteGuard<'b> {
    type Target = ManagedGroup;

    fn deref(&self) -> &ManagedGroup {
        // We can unwrap here, as we checked if the entry is present before
        // creating the guard. Also, since we hold a read lock on the `HashMap`,
        // the entry can't have been removed in the meantime.
        self.gs.get(self.index).unwrap()
    }
}

impl<'b> DerefMut for MGWriteGuard<'b> {
    fn deref_mut(&mut self) -> &mut ManagedGroup {
        // We can unwrap here, as we checked if the entry is present before
        // creating the guard. Also, since we hold a write lock on the `HashMap`,
        // the entry can't have been removed in the meantime.
        self.gs.get_mut(self.index).unwrap()
    }
}

impl<'b> Deref for MGReadGuard<'b> {
    type Target = ManagedGroup;

    fn deref(&self) -> &ManagedGroup {
        // We can unwrap here, as we checked if the entry is present before
        // creating the guard. Also, since we hold a read lock on the `HashMap`,
        // the entry can't have been removed in the meantime.
        self.gs.get(self.index).unwrap()
    }
}

impl Groups {
    pub(crate) fn contains_group(&self, group_id: &GroupId) -> Result<bool, ManagedClientError> {
        let gs = self
            .group_states
            .read()
            .map_err(|_| ManagedClientError::PoisonError)?;
        Ok(gs.contains_key(group_id))
    }

    pub(crate) fn get<'a>(
        &'a self,
        group_id: &'a GroupId,
    ) -> Result<MGReadGuard, ManagedClientError> {
        let gs = self
            .group_states
            .read()
            .map_err(|_| ManagedClientError::PoisonError)?;
        if !gs.contains_key(group_id) {
            return Err(ManagedClientError::NoMatchingGroup);
        }
        Ok(MGReadGuard {
            gs,
            index: group_id,
        })
    }

    pub(crate) fn get_mut<'a>(
        &'a self,
        group_id: &'a GroupId,
    ) -> Result<MGWriteGuard, ManagedClientError> {
        let gs: RwLockWriteGuard<HashMap<GroupId, ManagedGroup>> = self
            .group_states
            .write()
            .map_err(|_| ManagedClientError::PoisonError)?;
        if !gs.contains_key(&group_id) {
            return Err(ManagedClientError::NoMatchingGroup);
        }
        Ok(MGWriteGuard {
            gs,
            index: group_id,
        })
    }

    pub(crate) fn insert(
        &self,
        group_id: GroupId,
        managed_group: ManagedGroup,
    ) -> Result<(), ManagedClientError> {
        // Check if the GroupId is already taken.
        if self
            .group_states
            .read()
            .map_err(|_| ManagedClientError::PoisonError)?
            .contains_key(&group_id)
        {
            return Err(ManagedClientError::DuplicateGroupId);
        }
        let mut gs = self
            .group_states
            .write()
            .map_err(|_| ManagedClientError::PoisonError)?;
        gs.insert(group_id, managed_group);
        Ok(())
    }
}
