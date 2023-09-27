use std::{env, path::PathBuf};

pub fn get_file_path(file_name: &String) -> PathBuf {
    let tmp_folder = env::temp_dir();
    tmp_folder.join(file_name)
}
