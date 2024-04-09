use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::key_package::KeyPackage {
    type Public = public_types::key_package::KeyPackage;
    fn from_public_unchecked(key_pkg: public_types::key_package::KeyPackage) -> Self {
        Self {
            payload: private_types::key_package::KeyPackageTbs::from_public_unchecked(
                key_pkg.payload,
            ),
            signature: private_types::Signature::from_public_unchecked(key_pkg.signature),
        }
    }
}

impl PrivateSpecType for private_types::key_package::KeyPackageTbs {
    type Public = public_types::key_package::KeyPackageTbs;
    fn from_public_unchecked(payload: public_types::key_package::KeyPackageTbs) -> Self {
        Self {
            protocol_version: private_types::ProtocolVersion::from_public_unchecked(
                payload.protocol_version,
            ),
            ciphersuite: private_types::Ciphersuite::from_public_unchecked(payload.ciphersuite),
            init_key: private_types::keys::InitKey::from_public_unchecked(payload.init_key),
            leaf_node: private_types::tree::LeafNode::from_public_unchecked(payload.leaf_node),
            extensions: private_types::extensions::Extensions::from_public_unchecked(
                payload.extensions,
            ),
        }
    }
}

impl PrivateSpecType for private_types::key_package::KeyPackageRef {
    type Public = public_types::key_package::KeyPackageRef;
    fn from_public_unchecked(key_pkg_ref: public_types::key_package::KeyPackageRef) -> Self {
        Self(private_types::HashReference::from_public_unchecked(
            key_pkg_ref.0,
        ))
    }
}
