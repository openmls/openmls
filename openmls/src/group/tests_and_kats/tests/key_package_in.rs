use crate::test_utils::frankenstein::*;
use crate::test_utils::single_group_test_framework::*;

use crate::prelude::{KeyPackageIn, KeyPackageVerifyError, ProtocolVersion};

use tls_codec::VLBytes;

macro_rules! test_valn0108 {
    ($franken_key_package:expr, $crypto:expr, $should_succeed:expr) => {
        // Convert into KeyPackageIn
        let key_package_in: KeyPackageIn = $franken_key_package.into();

        // Validate
        let result = key_package_in.validate($crypto, ProtocolVersion::default());

        // Compare the result to expected result
        if $should_succeed {
            assert!(result.is_ok());
        } else {
            // Test that the correct error was returned
            assert_eq!(
                result,
                Err(KeyPackageVerifyError::InvalidLeafNodeSourceType)
            );
        }
    };
}

#[cfg(test)]
impl FrankenKeyPackage {
    fn with_leaf_node_source(mut self, source: FrankenLeafNodeSource) -> Self {
        self.payload.leaf_node.payload.leaf_node_source = source;

        self
    }
}

// Verify the `leaf_node_source` field: if the LeafNode appears in a KeyPackage,
// verify that `leaf_node_source` is set to `key_package`.
// This function tests each of the possible enum variants for LeafNodeSource.
#[openmls_test::openmls_test]
fn valn0108() {
    // Generate state for Alice
    let alice_party = CorePartyState::<Provider>::new("alice");
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let alice_key_package = alice_pre_group.key_package_bundle.key_package();

    // Construct a `FrankenKeyPackage` from the `KeyPackage`
    let franken_key_package = FrankenKeyPackage::from(alice_key_package.clone());

    // Test unmodified case with variant `KeyPackage`
    assert!(matches!(
        franken_key_package
            .payload
            .leaf_node
            .payload
            .leaf_node_source,
        FrankenLeafNodeSource::KeyPackage(_)
    ));
    test_valn0108!(
        franken_key_package.clone(),
        alice_party.provider.crypto(),
        true
    );

    // Incorrect case with variant `Update`
    let updated_key_package = franken_key_package
        .clone()
        .with_leaf_node_source(FrankenLeafNodeSource::Update);
    test_valn0108!(updated_key_package, alice_party.provider.crypto(), false);

    // Incorrect case with variant `Commit`
    let updated_key_package = franken_key_package
        .clone()
        .with_leaf_node_source(FrankenLeafNodeSource::Commit(VLBytes::new(vec![1; 32])));
    test_valn0108!(updated_key_package, alice_party.provider.crypto(), false);
}
