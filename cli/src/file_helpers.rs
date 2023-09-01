use std::{env, path::PathBuf};

pub fn get_file_path(prefix: &String, user_name: &String, suffix: Option<String>) -> PathBuf {
    let mut output_file_name: String = prefix.to_owned() + user_name;
    match suffix {
        Some(s) => output_file_name += &(s.to_owned() + ".json"),
        None => output_file_name += ".json",
    }
    let tmp_folder = env::temp_dir();
    let ks_path = tmp_folder.join(output_file_name);
    return ks_path;
}
