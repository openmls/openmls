use std::{collections::HashMap, env, fs::File, path::PathBuf};

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
}

impl Drop for SerializableKeyStore {
    fn drop(&mut self) {
        for (mut key, mut value) in self.values.drain() {
            super::zeroize_string(&mut key);
            super::zeroize_string(&mut value);
        }
    }
}

pub fn get_file_path(file_name: &String) -> PathBuf {
    let tmp_folder = env::temp_dir();
    tmp_folder.join(file_name)
}

impl super::MemoryStorage {
    fn get_file_path(user_name: &str) -> PathBuf {
        get_file_path(&("openmls_cli_".to_owned() + user_name + "_ks.json"))
    }

    pub fn save_to_file(&self, output_file: &File) -> Result<(), String> {
        let mut ser_ks = SerializableKeyStore::default();
        for (key, value) in &*self.values.read().unwrap() {
            ser_ks.values.insert(
                base64::prelude::BASE64_STANDARD.encode(key),
                base64::prelude::BASE64_STANDARD.encode(value),
            );
        }

        // Write directly to the caller's file instead of retaining another
        // buffered JSON copy in memory. `SerializableKeyStore` wipes its
        // base64-encoded key and value copies when it goes out of scope.
        match serde_json::to_writer_pretty(output_file, &ser_ks) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn save(&self, user_name: String) -> Result<(), String> {
        let ks_output_path = Self::get_file_path(&user_name);

        match File::create(ks_output_path) {
            Ok(output_file) => self.save_to_file(&output_file),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn load_from_file(&mut self, input_file: &File) -> Result<(), String> {
        // Read the JSON contents of the file as an instance of
        // `SerializableKeyStore`.
        match serde_json::from_reader::<&File, SerializableKeyStore>(input_file) {
            Ok(mut ser_ks) => {
                let mut ks_map = self.values.write().unwrap();
                for (key, value) in ser_ks.values.drain() {
                    // Base64 text is still sensitive because it reversibly
                    // encodes storage keys and values. Keep both text and
                    // decoded intermediates zeroizing until the map owns its
                    // replacement copies.
                    let key = Zeroizing::new(key);
                    let value = Zeroizing::new(value);
                    let decoded_key = match base64::prelude::BASE64_STANDARD.decode(key.as_bytes())
                    {
                        Ok(decoded_key) => Zeroizing::new(decoded_key),
                        Err(error) => return Err(error.to_string()),
                    };
                    let decoded_value =
                        match base64::prelude::BASE64_STANDARD.decode(value.as_bytes()) {
                            Ok(decoded_value) => Zeroizing::new(decoded_value),
                            Err(error) => return Err(error.to_string()),
                        };
                    super::insert_zeroizing(
                        &mut ks_map,
                        decoded_key.as_slice().to_vec(),
                        decoded_value.as_slice().to_vec(),
                    );
                }
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn load(&mut self, user_name: String) -> Result<(), String> {
        let ks_input_path = Self::get_file_path(&user_name);

        match File::open(ks_input_path) {
            Ok(input_file) => self.load_from_file(&input_file),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn loading_persistence_wipes_replaced_map_rows() {
        super::super::reset_zeroized_byte_count();
        let storage = &mut super::super::MemoryStorage::default();
        super::super::insert_zeroizing(
            storage.values.get_mut().unwrap(),
            b"key".to_vec(),
            b"old".to_vec(),
        );

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "openmls-memory-storage-persistence-{}-{nonce}.json",
            process::id()
        ));

        {
            let mut file = File::create(&path).unwrap();
            file.write_all(br#"{"values":{"a2V5":"bmV3"}}"#).unwrap();
        }

        let input = File::open(&path).unwrap();
        storage.load_from_file(&input).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(super::super::zeroized_byte_count(), 6);
        assert_eq!(
            storage.values.read().unwrap().get(b"key".as_slice()),
            Some(&b"new".to_vec())
        );
    }

    #[test]
    fn serializable_key_store_wipes_encoded_entries_on_drop() {
        super::super::reset_zeroized_byte_count();
        let mut key_store = SerializableKeyStore::default();
        key_store
            .values
            .insert("encoded-key".to_owned(), "encoded-value".to_owned());
        drop(key_store);
        assert_eq!(super::super::zeroized_byte_count(), 24);
    }
}
