use crate::group::{
    create_commit::CreateCommitParams,
    mls_group::{FramingParameters, Proposal, WireFormat},
};

// Tests that the builder for CreateCommitParams works as expected
#[openmls_test::openmls_test]
fn build_create_commit_params<Provider: OpenMlsProvider>(provider: &Provider) {
    let _ = provider;
    let framing_parameters: FramingParameters =
        FramingParameters::new(&[1, 2, 3], WireFormat::PrivateMessage);
    let inline_proposals: Vec<Proposal> = vec![];
    let force_self_update: bool = true;

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .inline_proposals(inline_proposals.clone())
        .force_self_update(force_self_update)
        .build();

    assert_eq!(params.framing_parameters(), &framing_parameters);
    assert_eq!(params.inline_proposals(), inline_proposals);
    assert_eq!(params.force_self_update(), force_self_update);
}
