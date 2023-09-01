use std::{env, path::PathBuf};

pub fn get_file_path(prefix: &String, user_name: &String, suffix: Option<String>) -> PathBuf {
    let output_file_name: String;
    match suffix {
        Some(s) => output_file_name = prefix.to_owned() + user_name + &s + ".json",
        None => output_file_name = prefix.to_owned() + user_name + "_ks.json",
    }
    let tmp_folder = env::temp_dir();
    let ks_path = tmp_folder.join(output_file_name);
    return ks_path;
}
