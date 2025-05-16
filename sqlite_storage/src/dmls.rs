use std::{borrow::Borrow, ops::Deref as _};

use openmls_traits::dmls_traits::DmlsStorageProvider;
use rusqlite::{params, Connection};

use crate::{Codec, SqliteStorageProvider, STORAGE_PROVIDER_VERSION};

impl<C: Codec, ConnectionRef: Borrow<Connection>> DmlsStorageProvider<STORAGE_PROVIDER_VERSION>
    for SqliteStorageProvider<C, ConnectionRef>
{
    fn storage_provider_for_epoch(&self, epoch: Vec<u8>) -> Self {
        self.clone_with_epoch(epoch)
    }

    fn clone_epoch_data(&self, destination_epoch: &[u8]) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        clone_encryption_key_pairs(connection, self.epoch(), destination_epoch)?;
        clone_group_data(connection, self.epoch(), destination_epoch)?;
        clone_epoch_key_pairs(connection, self.epoch(), destination_epoch)?;
        clone_own_leaf_nodes(connection, self.epoch(), destination_epoch)?;
        clone_proposals(connection, self.epoch(), destination_epoch)?;

        Ok(())
    }

    fn delete_epoch_data(&self) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        let epoch_id = self.epoch();

        delete_encryption_key_pairs(connection, epoch_id)?;
        delete_group_data(connection, epoch_id)?;
        delete_epoch_key_pairs(connection, epoch_id)?;
        delete_own_leaf_nodes(connection, epoch_id)?;
        delete_proposals(connection, epoch_id)?;

        Ok(())
    }

    fn epoch(&self) -> &[u8] {
        &self.epoch
    }
}

fn clone_encryption_key_pairs(
    connection: &Connection,
    origin_epoch_id: &[u8],
    destination_epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO openmls_encryption_keys (public_key, key_pair, provider_version, dmls_epoch_id) 
        SELECT public_key, key_pair, provider_version, ?1 
        FROM openmls_encryption_keys 
        WHERE dmls_epoch_id = ?2",
        params![destination_epoch_id, origin_epoch_id],
    )?;
    Ok(())
}

fn delete_encryption_key_pairs(
    connection: &Connection,
    epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM openmls_encryption_keys WHERE dmls_epoch_id = ?1",
        params![epoch_id],
    )?;
    Ok(())
}

fn clone_group_data(
    connection: &Connection,
    origin_epoch_id: &[u8],
    destination_epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO openmls_group_data (group_id, dmls_epoch_id, data_type, group_data, provider_version) 
        SELECT group_id, ?1, data_type, group_data, provider_version 
        FROM openmls_group_data 
        WHERE dmls_epoch_id = ?2",
        params![destination_epoch_id, origin_epoch_id],
    )?;
    Ok(())
}

fn delete_group_data(connection: &Connection, epoch_id: &[u8]) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM openmls_group_data WHERE dmls_epoch_id = ?1",
        params![epoch_id],
    )?;
    Ok(())
}

fn clone_epoch_key_pairs(
    connection: &Connection,
    origin_epoch_id: &[u8],
    destination_epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO openmls_epoch_keys_pairs (group_id, epoch_id, leaf_index, key_pairs, provider_version, dmls_epoch_id) 
        SELECT group_id, epoch_id, leaf_index, key_pairs, provider_version, ?1 
        FROM openmls_epoch_keys_pairs 
        WHERE dmls_epoch_id = ?2",
        params![destination_epoch_id, origin_epoch_id],
    )?;
    Ok(())
}

fn delete_epoch_key_pairs(connection: &Connection, epoch_id: &[u8]) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM openmls_epoch_keys_pairs WHERE dmls_epoch_id = ?1",
        params![epoch_id],
    )?;
    Ok(())
}

fn clone_own_leaf_nodes(
    connection: &Connection,
    origin_epoch_id: &[u8],
    destination_epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO openmls_own_leaf_nodes (group_id, leaf_node, provider_version, dmls_epoch_id) 
        SELECT group_id, leaf_node, provider_version, ?1 
        FROM openmls_own_leaf_nodes 
        WHERE dmls_epoch_id = ?2",
        params![destination_epoch_id, origin_epoch_id],
    )?;
    Ok(())
}

fn delete_own_leaf_nodes(connection: &Connection, epoch_id: &[u8]) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM openmls_own_leaf_nodes WHERE dmls_epoch_id = ?1",
        params![epoch_id],
    )?;
    Ok(())
}

fn clone_proposals(
    connection: &Connection,
    origin_epoch_id: &[u8],
    destination_epoch_id: &[u8],
) -> Result<(), rusqlite::Error> {
    connection.execute(
        "INSERT INTO openmls_proposals (group_id, dmls_epoch_id, proposal_ref, proposal, provider_version) 
        SELECT group_id, ?1, proposal_ref, proposal, provider_version 
        FROM openmls_proposals 
        WHERE dmls_epoch_id = ?2",
        params![destination_epoch_id, origin_epoch_id],
    )?;
    Ok(())
}

fn delete_proposals(connection: &Connection, epoch_id: &[u8]) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM openmls_proposals WHERE dmls_epoch_id = ?1",
        params![epoch_id],
    )?;
    Ok(())
}
