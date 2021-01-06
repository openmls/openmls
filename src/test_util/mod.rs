//! Test utilities
//!
#![allow(dead_code)]

use serde::{self, de::DeserializeOwned, Serialize};
use std::{
    fs::File,
    io::{BufReader, Write},
};

pub fn write(file_name: &str, obj: impl Serialize) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
    };
    file.write_all(
        serde_json::to_string(&obj)
            .expect("Error serializing test vectors")
            .as_bytes(),
    )
    .expect("Error writing test vector file");
}

pub fn read<T: DeserializeOwned>(file_name: &str) -> T {
    let file = match File::open(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
    };
    let reader = BufReader::new(file);
    match serde_json::from_reader(reader) {
        Ok(r) => return r,
        Err(e) => panic!("Error reading file.\n{:?}", e),
    };
}
