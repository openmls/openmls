//! The types naming the capabilities policy must be reachable from outside the
//! crate: they appear in the signatures of `MlsGroupBuilder`,
//! `MlsGroupCreateConfigBuilder`, `KeyPackageBuilder` and
//! `LeafNodeParametersBuilder`, and in the `LeafNodeBuild` error variants.
//! Every other test for them lives inside the crate, which is how the gap went
//! unnoticed.

use openmls::prelude::*;

#[test]
fn capabilities_policy_is_nameable_through_the_prelude() {
    let _policies = [CapabilitiesPolicy::Reject, CapabilitiesPolicy::Widen];

    let _config = MlsGroupCreateConfig::builder()
        .capabilities_policy(CapabilitiesPolicy::Widen)
        .build();

    let _builder = MlsGroup::builder().with_capabilities_policy(CapabilitiesPolicy::Widen);

    let _kp_builder = KeyPackage::builder().capabilities_policy(CapabilitiesPolicy::Widen);

    let _leaf_params = LeafNodeParameters::builder()
        .with_capabilities_policy(CapabilitiesPolicy::Reject)
        .build();
}

#[test]
fn leaf_node_build_error_is_matchable_through_the_prelude() {
    fn classify(e: &LeafNodeBuildError) -> &'static str {
        match e {
            LeafNodeBuildError::LibraryError(_) => "library",
            LeafNodeBuildError::Validation(_) => "validation",
        }
    }
    let _ = classify;
}
