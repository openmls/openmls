# Structiagram

```mermaid
%%{init: {
            "er": {
                "layoutDirection": "LR",
                "entityPadding": 15,
                "useMaxWidth": false
            }
        }}%%
erDiagram
ABinaryTree {
    Vec_L leaf_nodes
    Vec_P parent_nodes
    L default_leaf
    P default_parent
}
AbDiff {
     original_tree
    BTreeMap_LeafNodeIndex,L leaf_diff
    BTreeMap_ParentNodeIndex,P parent_diff
    TreeSize size
    L default_leaf
    P default_parent
}
AddProposal {
    KeyPackage key_package
}
AddProposalIn {
    KeyPackageIn key_package
}
AeadKey {
    AeadType aead_mode
    SecretVLBytes value
}
AeadNonce {
}
AppAckProposal {
    Vec_MessageRange received_ranges
}
ApplicationIdExtension {
    VLBytes key_id
}
ApplicationMessage {
    Vec_u8 bytes
}
ApplyProposalsValues {
    bool path_required
    bool self_removed
    Vec_(LeafNodeIndex,AddProposal) invitation_list
    Vec_PreSharedKeyId presharedkeys
    Option_ExternalInitProposal external_init_proposal_option
    Option_Extensions extensions
}
AuthenticatedContent {
    WireFormat wire_format
    FramedContent content
    FramedContentAuthData auth
}
AuthenticatedContentIn {
    WireFormat wire_format
    FramedContentIn content
    FramedContentAuthData auth
}
AuthenticatedContentTbm {
     tbs_payload
     auth
}
BasicCredential {
    Vec_u8 header
    Vec_u8 identity
}
Capabilities {
    Vec_ProtocolVersion versions
    Vec_VerifiableCiphersuite ciphersuites
    Vec_ExtensionType extensions
    Vec_ProposalType proposals
    Vec_CredentialType credentials
}
Certificate {
    Vec_u8 cert_data
}
Client {
    Vec_u8 identity
    HashMap_Ciphersuite,CredentialWithKey credentials
    OpenMlsRustCrypto crypto
    RwLock_HashMap_GroupId,MlsGroup groups
}
Commit {
    Vec_ProposalOrRef proposals
    Option_UpdatePath path
}
CommitIn {
    Vec_ProposalOrRefIn proposals
    Option_UpdatePathIn path
}
CommitSecret {
    Secret secret
}
CommitValidationTestSetup {
    MlsGroup alice_group
    CredentialWithKeyAndSigner alice_credential
    MlsGroup bob_group
    MlsGroup charlie_group
}
ConfirmationKey {
    Secret secret
}
ConfirmationTag {
}
CoreGroup {
    PublicGroup public_group
    GroupEpochSecrets group_epoch_secrets
    LeafNodeIndex own_leaf_index
    bool use_ratchet_tree_extension
    MessageSecretsStore message_secrets_store
    ResumptionPskStore resumption_psk_store
}
CoreGroupBuilder {
    TempBuilderPG1 public_group_builder
    Option_CoreGroupConfig config
    Vec_PreSharedKeyId psk_ids
    usize max_past_epochs
}
CoreGroupConfig {
    bool add_ratchet_tree_extension
}
CreateCommitParams {
    FramingParameters_'a framing_parameters
     proposal_store
    Vec_Proposal inline_proposals
    bool force_self_update
    CommitType commit_type
    Option_CredentialWithKey credential_with_key
}
CreateCommitParamsBuilder {
    CreateCommitParams_'a ccp
}
CreateCommitResult {
    AuthenticatedContent commit
    Option_Welcome welcome_option
    StagedCommit staged_commit
    Option_GroupInfo group_info
}
Credential {
    CredentialType credential_type
    VLBytes serialized_credential_content
}
CredentialWithKey {
    Credential credential
    SignaturePublicKey signature_key
}
CredentialWithKeyAndSigner {
    CredentialWithKey credential_with_key
    SignatureKeyPair signer
}
CryptoBasicsTestCase {
    u16 cipher_suite
    RefHash ref_hash
    ExpandWithLabel expand_with_label
    DeriveSecret derive_secret
    DeriveTreeSecret derive_tree_secret
    SignWithLabel sign_with_label
    EncryptWithLabel encrypt_with_label
}
CryptoConfig {
    Ciphersuite ciphersuite
    ProtocolVersion version
}
DecryptPathParams {
    ProtocolVersion version
     update_path
    LeafNodeIndex sender_leaf_index
     exclusion_list
     group_context
}
DecryptedMessage {
    VerifiableAuthenticatedContentIn verifiable_content
}
DecryptionRatchet {
    VecDeque_Option_RatchetKeyMaterial past_secrets
    RatchetSecret ratchet_head
}
DeriveSecret {
    String secret
    String label
    String out
}
DeriveTreeSecret {
    String secret
    String label
    u32 generation
    u16 length
    String out
}
EncodedGroupSecrets {
     joiner_secret
    Option_&'aPathSecret path_secret
     psks
}
EncryptContext {
    VLBytes label
    VLBytes context
}
EncryptWithLabel {
    String r#priv
    String r#pub
    String label
    String context
    String plaintext
    String kem_output
    String ciphertext
}
EncryptedGroupSecrets {
    KeyPackageRef new_member
    HpkeCiphertext encrypted_group_secrets
}
EncryptionKey {
    HpkePublicKey key
}
EncryptionKeyPair {
    EncryptionKey public_key
    EncryptionPrivateKey private_key
}
EncryptionPrivateKey {
    HpkePrivateKey key
}
EncryptionSecret {
    Secret secret
}
EncryptionTestVector {
    u16 cipher_suite
    u32 n_leaves
    String encryption_secret
    String sender_data_secret
    SenderDataInfo sender_data_info
    Vec_LeafSequence leaves
}
Epoch {
    String tree_hash
    String commit_secret
    String psk_secret
    String confirmed_transcript_hash
    String group_context
    String joiner_secret
    String welcome_secret
    String init_secret
    String sender_data_secret
    String encryption_secret
    String exporter_secret
    String epoch_authenticator
    String external_secret
    String confirmation_key
    String membership_key
    String resumption_psk
    String external_pub
    Exporter exporter
}
EpochAuthenticator {
    Secret secret
}
EpochKeypairId {
}
EpochSecret {
    Secret secret
}
EpochSecrets {
    InitSecret init_secret
    SenderDataSecret sender_data_secret
    EncryptionSecret encryption_secret
    ExporterSecret exporter_secret
    EpochAuthenticator epoch_authenticator
    ExternalSecret external_secret
    ConfirmationKey confirmation_key
    MembershipKey membership_key
    ResumptionPskSecret resumption_psk
}
EpochTree {
    u64 epoch
    MessageSecrets message_secrets
    Vec_Member leaves
}
ErrorString {
}
ExpandWithLabel {
    String secret
    String label
    String context
    u16 length
    String out
}
Exporter {
    String label
    String context
    u32 length
    String secret
}
ExporterSecret {
    Secret secret
}
Extensions {
    Vec_Extension unique
}
ExternalInitProposal {
    VLBytes kem_output
}
ExternalProposal {
}
ExternalPsk {
    VLBytes psk_id
}
ExternalPskTest {
    Vec_u8 psk_id
    Vec_u8 psk
}
ExternalPubExtension {
    HpkePublicKey external_pub
}
ExternalSecret {
    Secret secret
}
ExternalSender {
    SignaturePublicKey signature_key
    Credential credential
}
FramedContent {
    GroupId group_id
    GroupEpoch epoch
    Sender sender
    VLBytes authenticated_data
    FramedContentBody body
}
FramedContentAuthData {
    Signature signature
    Option_ConfirmationTag confirmation_tag
}
FramedContentIn {
    GroupId group_id
    GroupEpoch epoch
    Sender sender
    VLBytes authenticated_data
    FramedContentBodyIn body
}
FramedContentTbs {
    ProtocolVersion version
    WireFormat wire_format
    FramedContent content
    Option_Vec_u8 serialized_context
}
FramedContentTbsIn {
    ProtocolVersion version
    WireFormat wire_format
    FramedContentIn content
    Option_Vec_u8 serialized_context
}
FramingParameters {
     aad
    WireFormat wire_format
}
Group {
    GroupId group_id
    Vec_(usize,Vec_u8) members
    Ciphersuite ciphersuite
    MlsGroupJoinConfig group_config
    RatchetTree public_tree
    Vec_u8 exporter_secret
}
GroupCandidate {
    Vec_u8 identity
    KeyPackage key_package
    EncryptionKeyPair encryption_keypair
    HpkeKeyPair init_keypair
    SignatureKeyPair signature_keypair
    CredentialWithKeyAndSigner credential_with_key_and_signer
}
GroupContext {
    ProtocolVersion protocol_version
    Ciphersuite ciphersuite
    GroupId group_id
    GroupEpoch epoch
    VLBytes tree_hash
    VLBytes confirmed_transcript_hash
    Extensions extensions
}
GroupContextExtensionProposal {
    Extensions extensions
}
GroupEpoch {
}
GroupEpochSecrets {
    InitSecret init_secret
    ExporterSecret exporter_secret
    EpochAuthenticator epoch_authenticator
    ExternalSecret external_secret
    ResumptionPskSecret resumption_psk
}
GroupId {
    VLBytes value
}
GroupInfo {
    GroupInfoTBS payload
    Signature signature
}
GroupInfoTBS {
    GroupContext group_context
    Extensions extensions
    ConfirmationTag confirmation_tag
    LeafNodeIndex signer
}
GroupSecrets {
    JoinerSecret joiner_secret
    Option_PathSecret path_secret
    Vec_PreSharedKeyId psks
}
HashReference {
    VLBytes value
}
InitKey {
    HpkePublicKey key
}
InitSecret {
    Secret secret
}
IntermediateSecret {
    Secret secret
}
JoinProposal {
}
JoinerSecret {
    Secret secret
}
KdfLabel {
    u16 length
    VLBytes label
    VLBytes context
}
KeyPackage {
    KeyPackageTbs payload
    Signature signature
}
KeyPackageBuilder {
    Option_Lifetime key_package_lifetime
    Option_Extensions key_package_extensions
    Option_Capabilities leaf_node_capabilities
    Option_Extensions leaf_node_extensions
    bool last_resort
}
KeyPackageBundle {
    KeyPackage key_package
    HpkePrivateKey private_key
}
KeyPackageCreationResult {
    KeyPackage key_package
    EncryptionKeyPair encryption_keypair
    HpkePrivateKey init_private_key
}
KeyPackageIn {
    KeyPackageTbsIn payload
    Signature signature
}
KeyPackageTbs {
    ProtocolVersion protocol_version
    Ciphersuite ciphersuite
    InitKey init_key
    LeafNode leaf_node
    Extensions extensions
}
KeyPackageTbsIn {
    ProtocolVersion protocol_version
    Ciphersuite ciphersuite
    InitKey init_key
    LeafNodeIn leaf_node
    Extensions extensions
}
KeySchedule {
    Ciphersuite ciphersuite
    Option_IntermediateSecret intermediate_secret
    Option_EpochSecret epoch_secret
    State state
}
KeyScheduleTestVector {
    u16 cipher_suite
    String group_id
    String initial_init_secret
    Vec_Epoch epochs
}
LastResortExtension {
}
Leaf {
    u32 generation
    String application_key
    String application_nonce
    String handshake_key
    String handshake_nonce
}
LeafNode {
    LeafNodePayload payload
    Signature signature
}
LeafNodeIn {
    LeafNodePayload payload
    Signature signature
}
LeafNodeIndex {
}
LeafNodeInfoTest {
    LeafNodeIndex index
    Vec_EncryptionKeyPair encryption_keys
    SignatureKeyPair signature_keypair
}
LeafNodePayload {
    EncryptionKey encryption_key
    SignaturePublicKey signature_key
    Credential credential
    Capabilities capabilities
    LeafNodeSource leaf_node_source
    Extensions extensions
}
LeafNodeTbs {
    LeafNodePayload payload
    TreeInfoTbs tree_info_tbs
}
LeafPrivateTest {
    u32 index
    Vec_u8 encryption_priv
    Vec_u8 signature_priv
    Vec_PathSecretTest path_secrets
}
LeafSequence {
    u32 generations
    Vec_RatchetStep handshake
    Vec_RatchetStep application
}
LibraryError {
    InternalLibraryError internal
}
Lifetime {
    u64 not_before
    u64 not_after
}
Mac {
    VLBytes mac_value
}
Member {
    LeafNodeIndex index
    Credential credential
    Vec_u8 encryption_key
    Vec_u8 signature_key
}
MemberStagedCommitState {
    GroupEpochSecrets group_epoch_secrets
    MessageSecrets message_secrets
    StagedPublicGroupDiff staged_diff
    Vec_EncryptionKeyPair new_keypairs
    Option_EncryptionKeyPair new_leaf_keypair_option
    Option_LeafNode update_path_leaf_node
}
MembershipKey {
    Secret secret
}
MembershipTag {
}
MessageProtectionTest {
    u16 cipher_suite
    String group_id
    u64 epoch
    String tree_hash
    String confirmed_transcript_hash
    String signature_priv
    String signature_pub
    String encryption_secret
    String sender_data_secret
    String membership_key
    String proposal
    String proposal_pub
    String proposal_priv
    String commit
    String commit_pub
    String commit_priv
    String application
    String application_priv
}
MessageRange {
    KeyPackageRef sender
    u32 first_generation
    u32 last_generation
}
MessageSecrets {
    SenderDataSecret sender_data_secret
    MembershipKey membership_key
    ConfirmationKey confirmation_key
    Vec_u8 serialized_context
    SecretTree secret_tree
}
MessageSecretsStore {
    usize max_epochs
    VecDeque_EpochTree past_epoch_trees
    MessageSecrets message_secrets
}
MessagesTestVector {
    Vec_u8 mls_welcome
    Vec_u8 mls_group_info
    Vec_u8 mls_key_package
    Vec_u8 ratchet_tree
    Vec_u8 group_secrets
    Vec_u8 add_proposal
    Vec_u8 update_proposal
    Vec_u8 remove_proposal
    Vec_u8 pre_shared_key_proposal
    Vec_u8 re_init_proposal
    Vec_u8 external_init_proposal
    Vec_u8 group_context_extensions_proposal
    Vec_u8 commit
    Vec_u8 public_message_application
    Vec_u8 public_message_proposal
    Vec_u8 public_message_commit
    Vec_u8 private_message
}
MlsGroup {
    MlsGroupJoinConfig mls_group_config
    CoreGroup group
    ProposalStore proposal_store
    Vec_LeafNode own_leaf_nodes
    Vec_u8 aad
    MlsGroupState group_state
    InnerState state_changed
}
MlsGroupBuilder {
    Option_GroupId group_id
    MlsGroupCreateConfigBuilder mls_group_create_config_builder
}
MlsGroupCreateConfig {
    Capabilities capabilities
    Lifetime lifetime
    CryptoConfig crypto_config
    MlsGroupJoinConfig join_config
    Extensions group_context_extensions
    Extensions leaf_node_extensions
}
MlsGroupCreateConfigBuilder {
    MlsGroupCreateConfig config
}
MlsGroupJoinConfig {
    WireFormatPolicy wire_format_policy
    usize padding_size
    usize max_past_epochs
    usize number_of_resumption_psks
    bool use_ratchet_tree_extension
    SenderRatchetConfiguration sender_ratchet_configuration
}
MlsGroupJoinConfigBuilder {
    MlsGroupJoinConfig join_config
}
MlsGroupTestSetup {
    RwLock_HashMap_Vec_u8,RwLock_Client clients
    RwLock_HashMap_GroupId,Group groups
    RwLock_HashMap_Vec_u8,Vec_u8 waiting_for_welcome
    MlsGroupCreateConfig default_mgp
    CodecUse use_codec
}
MlsMessageHeader {
    GroupId group_id
    GroupEpoch epoch
    LeafNodeIndex sender
}
MlsMessageIn {
    ProtocolVersion version
    MlsMessageBodyIn body
}
MlsMessageOut {
    ProtocolVersion version
    MlsMessageBodyOut body
}
MlsSenderData {
    LeafNodeIndex leaf_index
    u32 generation
    ReuseGuard reuse_guard
}
MlsSenderDataAad {
    GroupId group_id
    GroupEpoch epoch
    ContentType content_type
}
MySignature {
}
NewLeafNodeParams {
    CryptoConfig config
    CredentialWithKey credential_with_key
    LeafNodeSource leaf_node_source
    Capabilities capabilities
    Extensions extensions
    TreeInfoTbs tree_info_tbs
}
OpenMlsSignaturePublicKey {
    SignatureScheme signature_scheme
    VLBytes value
}
OrderedProposalRefs {
    HashSet_ProposalRef proposal_refs
    Vec_ProposalRef ordered_proposal_refs
}
ParentNode {
    EncryptionKey encryption_key
    VLBytes parent_hash
    UnmergedLeaves unmerged_leaves
}
ParentNodeIndex {
}
ParsedSignWithLabel {
    SignatureKeyPair key
    Vec_u8 content
    String label
    Signature signature
}
PassiveClient {
    OpenMlsRustCrypto provider
    MlsGroupJoinConfig group_config
    Option_MlsGroup group
}
PassiveClientWelcomeTestVector {
    u16 cipher_suite
    Vec_ExternalPskTest external_psks
    Vec_u8 key_package
    Vec_u8 signature_priv
    Vec_u8 encryption_priv
    Vec_u8 init_priv
    Vec_u8 welcome
    Option_VecU8 ratchet_tree
    Vec_u8 initial_epoch_authenticator
    Vec_TestEpoch epochs
}
PathComputationResult {
    Option_CommitSecret commit_secret
    Option_UpdatePath encrypted_path
    Option_Vec_PlainUpdatePathNode plain_path
    Vec_EncryptionKeyPair new_keypairs
}
PathSecret {
    Secret path_secret
}
PathSecretTest {
    u32 node
    Vec_u8 path_secret
}
PathTest {
    u32 sender
    Vec_u8 update_path
    Vec_Option_String path_secrets
    Vec_u8 commit_secret
    Vec_u8 tree_hash_after
}
PlainUpdatePathNode {
    EncryptionKey public_key
    PathSecret path_secret
}
PreSharedKeyId {
    Psk psk
    VLBytes psk_nonce
}
PreSharedKeyProposal {
    PreSharedKeyId psk
}
PrivateContentAad {
    GroupId group_id
    GroupEpoch epoch
    ContentType content_type
    VLByteSlice_'a authenticated_data
}
PrivateMessage {
    GroupId group_id
    GroupEpoch epoch
    ContentType content_type
    VLBytes authenticated_data
    VLBytes encrypted_sender_data
    VLBytes ciphertext
}
PrivateMessageContent {
    FramedContentBody content
    FramedContentAuthData auth
    usize length_of_padding
}
PrivateMessageContentIn {
    FramedContentBodyIn content
    FramedContentAuthData auth
}
PrivateMessageIn {
    GroupId group_id
    GroupEpoch epoch
    ContentType content_type
    VLBytes authenticated_data
    VLBytes encrypted_sender_data
    VLBytes ciphertext
}
ProcessedMessage {
    GroupId group_id
    GroupEpoch epoch
    Sender sender
    Vec_u8 authenticated_data
    ProcessedMessageContent content
    Credential credential
}
ProposalQueue {
    Vec_ProposalRef proposal_references
    HashMap_ProposalRef,QueuedProposal queued_proposals
}
ProposalStore {
    Vec_QueuedProposal queued_proposals
}
ProposalValidationTestSetup {
     alice_group
     bob_group
}
PskBundle {
    Secret secret
}
PskElement {
    Vec_u8 psk_id
    Vec_u8 psk
    Vec_u8 psk_nonce
}
PskLabel {
     id
    u16 index
    u16 count
}
PskSecret {
    Secret secret
}
PublicGroup {
    TreeSync treesync
    ProposalStore proposal_store
    GroupContext group_context
    Vec_u8 interim_transcript_hash
    ConfirmationTag confirmation_tag
}
PublicGroupBuilder {
    TreeSync treesync
    GroupContext group_context
    ConfirmationTag confirmation_tag
}
PublicGroupDiff {
    TreeSyncDiff_'a diff
    GroupContext group_context
    Vec_u8 interim_transcript_hash
    ConfirmationTag confirmation_tag
}
PublicMessage {
    FramedContent content
    FramedContentAuthData auth
    Option_MembershipTag membership_tag
}
PublicMessageIn {
    FramedContentIn content
    FramedContentAuthData auth
    Option_MembershipTag membership_tag
}
QueuedAddProposal {
     add_proposal
     sender
}
QueuedProposal {
    Proposal proposal
    ProposalRef proposal_reference
    Sender sender
    ProposalOrRefType proposal_or_ref_type
}
QueuedPskProposal {
     psk_proposal
     sender
}
QueuedRemoveProposal {
     remove_proposal
     sender
}
QueuedUpdateProposal {
     update_proposal
     sender
}
RatchetSecret {
    Secret secret
    Generation generation
}
RatchetStep {
    String key
    String nonce
    String plaintext
    String ciphertext
}
RatchetTree {
}
RatchetTreeExtension {
    RatchetTreeIn ratchet_tree
}
RatchetTreeIn {
}
ReInitProposal {
    GroupId group_id
    ProtocolVersion version
    Ciphersuite ciphersuite
    Extensions extensions
}
RefHash {
    String label
    String value
    String out
}
RemoveProposal {
    LeafNodeIndex removed
}
RequiredCapabilitiesExtension {
    Vec_ExtensionType extension_types
    Vec_ProposalType proposal_types
    Vec_CredentialType credential_types
}
ResumptionPsk {
    ResumptionPskUsage usage
    GroupId psk_group_id
    GroupEpoch psk_epoch
}
ResumptionPskSecret {
    Secret secret
}
ReuseGuard {
     value
}
Secret {
    Ciphersuite ciphersuite
    SecretVLBytes value
    ProtocolVersion mls_version
}
SecretTree {
    u16 cipher_suite
    String encryption_secret
    SenderData sender_data
    Vec_Vec_Leaf leaves
}
SecretTreeNode {
    Secret secret
}
SenderData {
    String sender_data_secret
    String ciphertext
    String key
    String nonce
}
SenderDataInfo {
    String ciphertext
    String key
    String nonce
}
SenderDataSecret {
    Secret secret
}
SenderExtensionIndex {
}
SenderRatchetConfiguration {
    Generation out_of_order_tolerance
    Generation maximum_forward_distance
}
SerializedMlsGroup {
    MlsGroupJoinConfig mls_group_config
    CoreGroup group
    ProposalStore proposal_store
    Vec_LeafNode own_leaf_nodes
    Vec_u8 aad
    ResumptionPskStore resumption_psk_store
    MlsGroupState group_state
}
SignContent {
    VLBytes label
    VLBytes content
}
SignWithLabel {
    String r#priv
    String r#pub
    String content
    String label
    String signature
}
SignWithLabelTest {
    SignatureKeyPair key
    Vec_u8 content
    String label
}
Signature {
    VLBytes value
}
SignaturePublicKey {
    VLBytes value
}
SortedIter {
    Peekable_I a
    Peekable_I b
    F cmp
    usize size
    usize counter
}
StagedAbDiff {
    BTreeMap_LeafNodeIndex,L leaf_diff
    BTreeMap_ParentNodeIndex,P parent_diff
    TreeSize size
}
StagedCommit {
    ProposalQueue staged_proposal_queue
    StagedCommitState state
}
StagedCoreWelcome {
    PublicGroup public_group
    GroupEpochSecrets group_epoch_secrets
    LeafNodeIndex own_leaf_index
    bool use_ratchet_tree_extension
    MessageSecretsStore message_secrets_store
    ResumptionPskStore resumption_psk_store
    VerifiableGroupInfo verifiable_group_info
    EncryptionKeyPair leaf_keypair
    Option_Vec_EncryptionKeyPair path_keypairs
}
StagedPublicGroupDiff {
    StagedTreeSyncDiff staged_diff
    GroupContext group_context
    Vec_u8 interim_transcript_hash
    ConfirmationTag confirmation_tag
}
StagedTreeSyncDiff {
    StagedMlsBinaryTreeDiff_TreeSyncLeafNode,TreeSyncParentNode diff
    Vec_u8 new_tree_hash
}
StagedWelcome {
    MlsGroupJoinConfig mls_group_config
    StagedCoreWelcome group
}
TempBuilderCCPM0 {
}
TempBuilderCCPM1 {
    FramingParameters_'a framing_parameters
}
TempBuilderPG1 {
    GroupId group_id
    CryptoConfig crypto_config
    CredentialWithKey credential_with_key
    Option_Lifetime lifetime
    Option_Capabilities capabilities
    Extensions leaf_node_extensions
    Extensions group_context_extensions
}
TempBuilderPG2 {
    TreeSync treesync
    GroupContext group_context
}
TestClient {
    HashMap_Ciphersuite,CredentialWithKeyAndSigner credentials
    RefCell_Vec_KeyPackageBundle key_package_bundles
    RefCell_HashMap_GroupId,CoreGroup group_states
}
TestClientConfig {
     name
    Vec_Ciphersuite ciphersuites
}
TestElement {
    u16 cipher_suite
    Vec_PskElement psks
    Vec_u8 psk_secret
}
TestEpoch {
    Vec_TestProposal proposals
    Vec_u8 commit
    Vec_u8 epoch_authenticator
}
TestGroupConfig {
    Ciphersuite ciphersuite
    CoreGroupConfig config
    Vec_TestClientConfig members
}
TestProposal {
}
TestSetup {
    RefCell_HashMap_(&'staticstr,Ciphersuite),Vec_KeyPackage _key_store
    RefCell_HashMap_&'staticstr,RefCell_TestClient clients
}
TestSetupConfig {
    Vec_TestClientConfig clients
    Vec_TestGroupConfig groups
}
TranscriptTestVector {
    u16 cipher_suite
    Vec_u8 confirmation_key
    Vec_u8 authenticated_content
    Vec_u8 interim_transcript_hash_before
    Vec_u8 confirmed_transcript_hash_after
    Vec_u8 interim_transcript_hash_after
}
TreeContext {
    u32 node
    u32 generation
}
TreeHash {
}
TreeKemTest {
    u16 cipher_suite
    Vec_u8 group_id
    u64 epoch
    Vec_u8 confirmed_transcript_hash
    Vec_u8 ratchet_tree
    Vec_LeafPrivateTest leaves_private
    Vec_PathTest update_paths
}
TreeMathTestVector {
    u32 n_leaves
    u32 n_nodes
    u32 root
    Vec_Option_u32 left
    Vec_Option_u32 right
    Vec_Option_u32 parent
    Vec_Option_u32 sibling
}
TreePosition {
    GroupId group_id
    LeafNodeIndex leaf_index
}
TreeSize {
}
TreeSync {
    MlsBinaryTree_TreeSyncLeafNode,TreeSyncParentNode tree
    Vec_u8 tree_hash
}
TreeSyncDiff {
    MlsBinaryTreeDiff_'a,TreeSyncLeafNode,TreeSyncParentNode diff
}
TreeSyncLeafNode {
    Option_LeafNode node
}
TreeSyncParentNode {
    Option_ParentNode node
}
UnknownExtension {
}
UnmergedLeaves {
    Vec_LeafNodeIndex list
}
UnverifiedMessage {
    VerifiableAuthenticatedContentIn verifiable_content
    Credential credential
    OpenMlsSignaturePublicKey sender_pk
    Option_SenderContext sender_context
}
UpdatePath {
    LeafNode leaf_node
    Vec_UpdatePathNode nodes
}
UpdatePathIn {
    LeafNodeIn leaf_node
    Vec_UpdatePathNode nodes
}
UpdatePathNode {
    EncryptionKey public_key
    Vec_HpkeCiphertext encrypted_path_secrets
}
UpdateProposal {
    LeafNode leaf_node
}
UpdateProposalIn {
    LeafNodeIn leaf_node
}
ValidationTestSetup {
    MlsGroup alice_group
    MlsGroup bob_group
    CredentialWithKeyAndSigner _alice_credential
    CredentialWithKeyAndSigner _bob_credential
    KeyPackage _alice_key_package
    KeyPackage _bob_key_package
}
VecU8 {
}
VerifiableAuthenticatedContentIn {
    FramedContentTbsIn tbs
    FramedContentAuthData auth
}
VerifiableCommitLeafNode {
    LeafNodePayload payload
    Signature signature
    Option_TreePosition tree_position
}
VerifiableGroupInfo {
    GroupInfoTBS payload
    Signature signature
}
VerifiableKeyPackage {
    KeyPackageTbs payload
    Signature signature
}
VerifiableKeyPackageLeafNode {
    LeafNodePayload payload
    Signature signature
}
VerifiableUpdateLeafNode {
    LeafNodePayload payload
    Signature signature
    Option_TreePosition tree_position
}
Welcome {
    Ciphersuite cipher_suite
    Vec_EncryptedGroupSecrets secrets
    VLBytes encrypted_group_info
}
WelcomeSecret {
    Secret secret
}
WelcomeTestVector {
    u16 cipher_suite
    Vec_u8 init_priv
    Vec_u8 signer_pub
    Vec_u8 key_package
    Vec_u8 welcome
}
WireFormatPolicy {
    OutgoingWireFormatPolicy outgoing
    IncomingWireFormatPolicy incoming
}
FramedContent ||--|| Group : group_id
FramedContentIn ||--|| Group : group_id
Group ||--|| Group : group_id
GroupContext ||--|| Group : group_id
MlsGroupBuilder ||--|| Group : group_id
MlsMessageHeader ||--|| Group : group_id
MlsSenderDataAad ||--|| Group : group_id
PrivateContentAad ||--|| Group : group_id
PrivateMessage ||--|| Group : group_id
PrivateMessageIn ||--|| Group : group_id
ProcessedMessage ||--|| Group : group_id
ReInitProposal ||--|| Group : group_id
ResumptionPsk ||--|| Group : psk_group_id
TempBuilderPG1 ||--|| Group : group_id
TreePosition ||--|| Group : group_id
```
