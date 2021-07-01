use openmls::{
    prelude::Config,
    test_util::{read, write},
};

use kat_generation::kat_tree_kem::*;

#[test]
pub fn read_tree_kem_kat() {
    let tree_kem_tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tree_kem_tests {
        run_test_vector(test_vector).expect("error while checking tree kem test vector.");
    }
}

#[test]
pub fn write_tree_kem_kat() {
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 20;

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 2..NUM_LEAVES {
            log::trace!(" Creating test vector with {:?} leaves ...", n_leaves);
            let test = generate_test_vector(n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_tree_kem_openmls-new.json", &tests);
}
