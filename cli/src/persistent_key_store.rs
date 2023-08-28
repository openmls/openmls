use cocoon;
use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs::File, sync::RwLock, path::PathBuf, io::{BufWriter, BufReader}};

#[derive(Debug, Default)]
pub struct PersistentKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
}

impl OpenMlsKeyStore for PersistentKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = PersistentKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value =
            serde_json::to_vec(v).map_err(|_| PersistentKeyStoreError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            serde_json::from_slice(value).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(k);
        Ok(())
    }
}

impl PersistentKeyStore {
    fn get_file_path(user_name: &String) -> PathBuf {
        let output_file_name = "openmls_cli_".to_owned() + user_name.as_str() + "_ks.json";
        let tmp_folder = env::temp_dir();
        let ks_path = tmp_folder.join(output_file_name);
        return ks_path;
    }

    fn ciphered_save(&self, mut output_file: &File, password: String) {
        let mut ser_ks = SerializableKeyStore::default();
        for (key, value) in &*self.values.read().unwrap() {
            ser_ks
                .values
                .insert(base64::encode(key), base64::encode(value));
        }
        let cocoon = cocoon::Cocoon::new(password.as_bytes());
        
        match serde_json::to_string_pretty(&ser_ks) {
            Ok(s) => cocoon.dump(s.into_bytes(), &mut output_file).unwrap(),
            Err(e) => log::error!("Error serializing user keystore: {:?}", e.to_string()),
        }
    }

    fn unciphered_save(&self, output_file: &File) {
        let writer = BufWriter::new(output_file);

        let mut ser_ks = SerializableKeyStore::default();
        for (key, value) in &*self.values.read().unwrap() {
            ser_ks
                .values
                .insert(base64::encode(key), base64::encode(value));
        }
        
        match serde_json::to_writer_pretty(writer, &ser_ks) {
            Ok(()) => log::info!("User keystore serialized"),
            Err(e) => log::error!("Error serializing user keystore: {:?}", e.to_string()),
        }
    }

    pub fn save(&self, user_name: String, password: Option<String>) {
        let ks_output_path = PersistentKeyStore::get_file_path(&user_name);
        let output_file = File::create(ks_output_path).unwrap();
        match password {
            None => self.unciphered_save(&output_file),
            Some(p) => self.ciphered_save(&output_file, p),
        }
    }

    fn ciphered_load(&self, mut input_file: &File, password: String) {
        // Load file into a string.
        let cocoon = cocoon::Cocoon::new(password.as_bytes());

        let data = cocoon.parse(&mut input_file).unwrap();
        let text = String::from_utf8(data).expect("Found invalid UTF-8");

        let ser_ks = serde_json::from_str::<SerializableKeyStore>(&text).unwrap();
        let mut ks_map = self.values.write().unwrap();
        for (key, value) in ser_ks.values {
            ks_map.insert(base64::decode(key).unwrap(), base64::decode(value).unwrap());
        }
    }

    fn unciphered_load(&mut self, input_file: &File) {
        // Prepare file reader.
        let reader = BufReader::new(input_file);

        // Read the JSON contents of the file as an instance of `SerializableKeyStore`.
        let ser_ks: SerializableKeyStore = serde_json::from_reader(reader).unwrap();
        let mut ks_map = self.values.write().unwrap();
        for (key, value) in ser_ks.values {
            ks_map.insert(base64::decode(key).unwrap(), base64::decode(value).unwrap());
        }
    }

    pub fn load(&mut self, user_name: String, password: Option<String>) {
        let ks_input_path = PersistentKeyStore::get_file_path(&user_name);
        let input_file = File::open(ks_input_path).unwrap();
        match password {
            None => self.unciphered_load(&input_file),
            Some(p) => self.ciphered_load(&input_file, p),
        }
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum PersistentKeyStoreError {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}
