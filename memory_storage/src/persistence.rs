use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
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
        let writer = BufWriter::new(output_file);

        let mut ser_ks = SerializableKeyStore::default();
        for (key, value) in &*self.values.read().unwrap() {
            ser_ks.values.insert(
                base64::prelude::BASE64_STANDARD.encode(key),
                base64::prelude::BASE64_STANDARD.encode(value),
            );
        }

        match serde_json::to_writer_pretty(writer, &ser_ks) {
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
        // Prepare file reader.
        let reader = BufReader::new(input_file);

        // Read the JSON contents of the file as an instance of `SerializableKeyStore`.
        match serde_json::from_reader::<BufReader<&File>, SerializableKeyStore>(reader) {
            Ok(ser_ks) => {
                let mut ks_map = self.values.write().unwrap();
                for (key, value) in ser_ks.values {
                    ks_map.insert(
                        base64::prelude::BASE64_STANDARD.decode(key).unwrap(),
                        base64::prelude::BASE64_STANDARD.decode(value).unwrap(),
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
