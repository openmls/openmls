//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client in that repository.

#![allow(clippy::result_large_err)]

use std::{collections::HashMap, fmt::Display, fs::File, io::Write, sync::Mutex};

use clap::Parser;
#[allow(unused_imports)]
use clap_derive::*;
use mls_client::{
    mls_client_server::{MlsClient, MlsClientServer},
    *,
};
use mls_interop_proto::mls_client;
use openmls::{
    credentials::{BasicCredential, Credential, CredentialType, CredentialWithKey},
    extensions::{Extension, Extensions, ExternalSender, SenderExtensionIndex},
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        GroupContext, GroupEpoch, GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        StagedWelcome, WireFormatPolicy, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{
        external_proposals::{ExternalProposal, JoinProposal},
        proposals::ReInitProposal,
    },
    prelude::{
        Capabilities, LeafNodeIndex, ProposalOrRefType, Propose, SenderRatchetConfiguration,
    },
    schedule::{psk::ResumptionPskUsage, ExternalPsk, PreSharedKeyId, Psk},
    treesync::{LeafNodeParameters, RatchetTreeIn},
    versions::ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{random::OpenMlsRand, types::Ciphersuite, OpenMlsProvider};
use tls_codec::{Deserialize, Serialize, VLBytes};
use tonic::{async_trait, transport::Server, Code, Request, Response, Status};
use tracing::{debug, error, info, instrument, trace, Span};
use tracing_subscriber::EnvFilter;

const IMPLEMENTATION_NAME: &str = "OpenMLS";
const CREDENTIAL_TYPES: [CredentialType; 1] = [CredentialType::Basic];

/// This struct contains the state for a single MLS client. The interop client
/// doesn't consider scenarios where a credential is re-used across groups, so
/// this simple structure is sufficient.
pub struct InteropGroup {
    group: MlsGroup,
    wire_format_policy: WireFormatPolicy,
    signature_keys: SignatureKeyPair,
    messages_out: Vec<MlsMessageIn>,
    crypto_provider: OpenMlsRustCrypto,
}

type PendingState = (
    KeyPackageBundle,
    Credential,
    SignatureKeyPair,
    OpenMlsRustCrypto,
);

/// State for an external signer created via `create_external_signer` and later
/// used by `external_signer_proposal`. Keyed by the `u32` signer id we mint and
/// return to the test-runner. The signer is not a group member, so we only need
/// its signing keypair (the credential is retained for symmetry / debugging).
type ExternalSignerState = (SignatureKeyPair, Credential);

/// State captured after a member merges a ReInit commit (RFC 9420 §11.2). Keyed
/// by the `u32` `reinit_id` we mint and return to the test-runner. It carries
/// everything needed to later create (`re_init_welcome`) or join
/// (`handle_re_init_welcome`) the successor group:
/// * the index of the suspended old group in `groups` (used to seed the
///   successor via [`CommitBuilder::reinit`] / [`StagedWelcome::new_from_reinit`]),
/// * a fresh provider holding this member's freshly minted successor key package
///   and signer (the successor ciphersuite may use a different signature scheme),
/// * that key package bundle, signer and credential (same identity as before).
struct ReInitState {
    old_state_id: u32,
    crypto_provider: OpenMlsRustCrypto,
    signature_keys: SignatureKeyPair,
    credential: CredentialWithKey,
    key_package: KeyPackageBundle,
    wire_format_policy: WireFormatPolicy,
    // The ReInit proposal that was committed. It describes the successor
    // group's parameters and is needed both to create the successor group and
    // to validate it when joining (the old group no longer carries it).
    reinit_proposal: ReInitProposal,
}

/// This is the main state struct of the interop client. It keeps track of the
/// individual MLS clients, as well as pending key packages that it was told to
/// create. Pending key packages are keyed by their `u32` transaction id, which
/// the test-runner assigns per key package and echoes back (e.g. in `JoinGroup`
/// and `StorePsk`). Keying by transaction id -- rather than by identity, which
/// is reused across scenarios -- is what keeps concurrently running scenarios
/// from clobbering each other's pending key packages.
pub struct MlsClientImpl {
    groups: Mutex<Vec<InteropGroup>>,
    pending_state: Mutex<HashMap<u32, PendingState>>,
    external_signers: Mutex<HashMap<u32, ExternalSignerState>>,
    pending_reinits: Mutex<HashMap<u32, ReInitState>>,
}

impl MlsClientImpl {
    /// A simple constructor for `MlsClientImpl`.
    fn new() -> Self {
        MlsClientImpl {
            groups: Mutex::new(Vec::new()),
            pending_state: Mutex::new(HashMap::new()),
            external_signers: Mutex::new(HashMap::new()),
            pending_reinits: Mutex::new(HashMap::new()),
        }
    }

    // Lock accessors that recover from a poisoned mutex instead of panicking.
    //
    // The gRPC handlers do a lot of `.unwrap()`ing while holding these locks, so
    // a single failing request can panic mid-handler and poison the mutex. With
    // plain `.lock().unwrap()` that poison is permanent: every subsequent
    // request panics on lock acquisition and the server is bricked until it is
    // restarted. Recovering the guard via `into_inner()` keeps one bad request
    // from taking the whole server down with it.

    fn groups(&self) -> std::sync::MutexGuard<'_, Vec<InteropGroup>> {
        self.groups.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn pending_state(&self) -> std::sync::MutexGuard<'_, HashMap<u32, PendingState>> {
        self.pending_state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn external_signers(&self) -> std::sync::MutexGuard<'_, HashMap<u32, ExternalSignerState>> {
        self.external_signers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn pending_reinits(&self) -> std::sync::MutexGuard<'_, HashMap<u32, ReInitState>> {
        self.pending_reinits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// After a member has merged a ReInit commit (so `interop_group.group` is
    /// suspended), mint a fresh key package for the successor group, store the
    /// resulting [`ReInitState`], and build the response the runner expects.
    ///
    /// The successor ciphersuite (from the merged ReInit proposal) may use a
    /// different signature scheme, so a fresh signer/credential is generated
    /// while preserving the member's identity (credential equality — which the
    /// receiver checks — compares only the identity, not the signature key).
    fn build_reinit_state(
        &self,
        interop_group: &mut InteropGroup,
        old_state_id: u32,
        reinit_proposal: ReInitProposal,
    ) -> Result<HandleReInitCommitResponse, Status> {
        let successor_ciphersuite = reinit_proposal.ciphersuite();

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        // Preserve the member's identity across the reinitialization. Read it
        // from the own leaf node rather than `MlsGroup::credential()`, because
        // the group is already suspended (inactive) at this point and
        // `credential()` would return `UseAfterEviction`.
        let own_credential = interop_group
            .group
            .own_leaf_node()
            .ok_or_else(|| Status::internal("missing own leaf node"))?
            .credential()
            .clone();
        let identity = BasicCredential::try_from(own_credential)
            .map_err(|_| Status::internal("expected a basic credential"))?
            .identity()
            .to_vec();

        // Fresh provider + signer for the successor ciphersuite's signature
        // scheme. This provider will back the successor group.
        let crypto_provider = OpenMlsRustCrypto::default();
        let signature_keys = SignatureKeyPair::new(successor_ciphersuite.signature_algorithm())
            .map_err(|_| Status::internal("failed to create successor signer"))?;
        signature_keys
            .store(crypto_provider.storage())
            .map_err(into_status)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signature_keys.public().into(),
        };

        // Advertise support for the successor ciphersuite (plus the common
        // interop suites) so the successor group accepts this leaf.
        let mut ciphersuites = vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ];
        if !ciphersuites.contains(&successor_ciphersuite) {
            ciphersuites.push(successor_ciphersuite);
        }

        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(Capabilities::new(
                Some(&[ProtocolVersion::Mls10, ProtocolVersion::Other(999)]),
                Some(&ciphersuites),
                None,
                None,
                Some(&CREDENTIAL_TYPES),
            ))
            .build(
                successor_ciphersuite,
                &crypto_provider,
                &signature_keys,
                credential.clone(),
            )
            .map_err(|_| Status::internal("failed to build successor key package"))?;

        let key_package_bytes = MlsMessageOut::from(key_package.key_package().clone())
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize successor key package"))?;

        let reinit_id: [u8; 4] = crypto_provider.rand().random_array().unwrap();
        let reinit_id = u32::from_be_bytes(reinit_id);

        self.pending_reinits().insert(
            reinit_id,
            ReInitState {
                old_state_id,
                crypto_provider,
                signature_keys,
                credential,
                key_package,
                wire_format_policy: interop_group.wire_format_policy,
                reinit_proposal,
            },
        );

        Ok(HandleReInitCommitResponse {
            reinit_id,
            key_package: key_package_bytes,
            epoch_authenticator,
        })
    }
}

fn into_status<E: Display>(e: E) -> Status {
    let message = "mls group error ".to_string() + &e.to_string();
    error!("{message}");
    Status::new(Code::Aborted, message)
}

/// Rebuild `Extensions<GroupContext>` from the test-runner's proto extensions.
/// The runner splits each extension into its type and its raw data; we
/// re-serialize the TLS wire form (ExtensionType u16 || opaque<V> data) and let
/// OpenMLS parse it back. Known types get their structured variant; unknown
/// types become `Extension::Unknown`.
fn group_context_extensions_from_proto(
    extensions: &[mls_client::Extension],
) -> Result<Extensions<GroupContext>, Status> {
    let extensions = extensions
        .iter()
        .map(|ext| {
            let mut wire = Vec::new();
            (ext.extension_type as u16)
                .tls_serialize(&mut wire)
                .map_err(|_| Status::aborted("failed to serialize extension type"))?;
            VLBytes::new(ext.extension_data.clone())
                .tls_serialize(&mut wire)
                .map_err(|_| Status::aborted("failed to serialize extension data"))?;
            Extension::tls_deserialize(&mut wire.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize extension"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Extensions::<GroupContext>::from_vec(extensions)
        .map_err(|err| Status::aborted(format!("invalid group context extensions: {err}")))
}

fn to_ciphersuite(cs: u32) -> Result<&'static Ciphersuite, Status> {
    let cs_name = match Ciphersuite::try_from(cs as u16) {
        Ok(cs_name) => cs_name,
        Err(_) => {
            return Err(Status::new(
                Code::InvalidArgument,
                "ciphersuite not supported by OpenMLS",
            ));
        }
    };
    let ciphersuites = &[
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    ];
    match ciphersuites.iter().find(|&&cs| cs == cs_name) {
        Some(ciphersuite) => Ok(ciphersuite),
        None => Err(Status::new(
            Code::InvalidArgument,
            "ciphersuite not supported by this configuration of OpenMLS",
        )),
    }
}

fn _into_bytes(obj: impl serde::Serialize) -> Vec<u8> {
    serde_json::to_string_pretty(&obj)
        .expect("Error serializing test vectors")
        .as_bytes()
        .to_vec()
}

pub fn write(file_name: &str, payload: &[u8]) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {file_name}."),
    };
    file.write_all(payload)
        .expect("Error writing test vector file");
}

// A helper function translating the bool in the protobuf to OpenMLS' WireFormat
pub fn wire_format_policy(encrypt: bool) -> WireFormatPolicy {
    match encrypt {
        false => PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        true => PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    }
}

fn ratchet_tree_from_config(bytes: Vec<u8>) -> Option<RatchetTreeIn> {
    debug!("Deserializing `RatchetTree`.");
    if !bytes.is_empty() {
        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(bytes.as_slice()).unwrap();
        debug!("Got `RatchetTree`.");
        trace!(?ratchet_tree);
        Some(ratchet_tree)
    } else {
        debug!("Skipping deserialization due to empty bytes.");
        None
    }
}

fn bytes_to_string<B>(bytes: B) -> String
where
    B: AsRef<[u8]>,
{
    let bytes = bytes.as_ref();

    match String::from_utf8(bytes.to_vec()) {
        Ok(string) => string,
        Err(error) => {
            error!(?error, "Using lossy UTF-8 conversion.");
            String::from_utf8_lossy(bytes).to_string()
        }
    }
}

#[async_trait]
impl MlsClient for MlsClientImpl {
    #[instrument(skip_all)]
    async fn name(&self, request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn supported_ciphersuites(
        &self,
        _request: Request<SupportedCiphersuitesRequest>,
    ) -> Result<Response<SupportedCiphersuitesResponse>, Status> {
        // TODO: read from provider
        let ciphersuites = &[
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ];
        let response = SupportedCiphersuitesResponse {
            ciphersuites: ciphersuites
                .iter()
                .map(|cs| u16::from(*cs) as u32)
                .collect(),
        };

        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let provider = OpenMlsRustCrypto::default();

        let ciphersuite = Ciphersuite::try_from(request.cipher_suite as u16).unwrap();
        let credential = BasicCredential::new(request.identity.clone());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys.store(provider.storage()).unwrap();

        let wire_format_policy = wire_format_policy(request.encrypt_handshake);
        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signature_keys,
            &mls_group_config,
            GroupId::from_slice(&request.group_id),
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(into_status)?;

        trace!(epoch=?group.epoch(), "Current group state.");

        let interop_group = InteropGroup {
            group,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider: provider,
        };

        let mut groups = self.groups();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = CreateGroupResponse { state_id };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn create_key_package(
        &self,
        request: Request<CreateKeyPackageRequest>,
    ) -> Result<Response<CreateKeyPackageResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let crypto_provider = OpenMlsRustCrypto::default();
        let ciphersuite = *to_ciphersuite(request.cipher_suite)?;
        let identity = request.identity.clone();

        debug!(
            r#for = String::from_utf8_lossy(&identity).to_string(),
            "Creating key package."
        );

        let credential = BasicCredential::new(identity);
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(Capabilities::new(
                Some(&[ProtocolVersion::Mls10, ProtocolVersion::Other(999)]),
                Some(&[
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ]),
                // The extensions capability MUST NOT list "default" extension
                // types (those defined in RFC 9420, i.e. types 1..=5). Support
                // for them is implied, and strict implementations (e.g. mls-rs)
                // reject a leaf node that lists them, silently dropping the Add
                // proposal for this key package. We support no non-default
                // extensions, so this list stays empty.
                None,
                None,
                Some(&CREDENTIAL_TYPES),
            ))
            .build(
                ciphersuite,
                &crypto_provider,
                &signature_keys,
                CredentialWithKey {
                    credential: credential.clone().into(),
                    signature_key: signature_keys.public().into(),
                },
            )
            .unwrap();

        let transaction_id: [u8; 4] = crypto_provider.rand().random_array().unwrap();
        let transaction_id = u32::from_be_bytes(transaction_id);

        let key_package_msg: MlsMessageOut = key_package.clone().into();
        let response = CreateKeyPackageResponse {
            transaction_id,
            key_package: key_package_msg
                .tls_serialize_detached()
                .expect("error serializing key package"),
            encryption_priv: key_package
                .encryption_private_key()
                .tls_serialize_detached()
                .unwrap(),
            init_priv: key_package
                .init_private_key()
                .tls_serialize_detached()
                .unwrap(),
            signature_priv: signature_keys.private().to_vec(),
        };

        self.pending_state().insert(
            transaction_id,
            (
                key_package,
                credential.into(),
                signature_keys,
                crypto_provider,
            ),
        );

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn join_group(
        &self,
        request: Request<JoinGroupRequest>,
    ) -> Result<Response<JoinGroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        trace!(identity = String::from_utf8_lossy(&request.identity).to_string());

        let wire_format_policy = wire_format_policy(request.encrypt_handshake);
        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();

        let mut pending_key_packages = self.pending_state();
        let (my_key_package, _my_credential, my_signature_keys, crypto_provider) =
            pending_key_packages
                .remove(&request.transaction_id)
                .ok_or(Status::aborted(format!(
                    "failed to find key package for transaction id {} (identity {:x?})",
                    request.transaction_id, request.identity
                )))?;

        use openmls_traits::storage::StorageProvider as _;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        crypto_provider
            .storage()
            .write_key_package(
                &my_key_package
                    .key_package()
                    .hash_ref(crypto_provider.crypto())
                    .map_err(into_status)?,
                &my_key_package,
            )
            .map_err(into_status)?;

        let welcome = MlsMessageIn::tls_deserialize(&mut request.welcome.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize MlsMessage with a Welcome"))?
            .into_welcome()
            .expect("expected a welcome");

        let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

        let group = StagedWelcome::new_from_welcome(
            &crypto_provider,
            &mls_group_config,
            welcome,
            ratchet_tree,
        )
        .map_err(into_status)?
        .into_group(&crypto_provider)
        .map_err(into_status)?;

        let interop_group = InteropGroup {
            wire_format_policy,
            group,
            signature_keys: my_signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        let mut groups = self.groups();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = JoinGroupResponse {
            state_id,
            epoch_authenticator,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn external_join(
        &self,
        request: Request<ExternalJoinRequest>,
    ) -> Result<Response<ExternalJoinResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        Span::current().record("actor", bytes_to_string(&request.identity));

        let (interop_group, commit) = {
            debug!("Deserializing `MlsMessageIn` (to obtain group info).");
            let verifiable_group_info = {
                let msg =
                    MlsMessageIn::tls_deserialize(&mut request.group_info.as_slice()).unwrap();

                match msg.extract() {
                    MlsMessageBodyIn::GroupInfo(verifiable_group_info) => verifiable_group_info,
                    other => panic!("Expected `MlsMessageBodyIn::GroupInfo`, got {other:?}."),
                }
            };
            debug!("Got `VerifiableGroupInfo`.");
            trace!(?verifiable_group_info);

            let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

            let provider = OpenMlsRustCrypto::default();
            let ciphersuite = verifiable_group_info.ciphersuite();

            let credential: Credential = BasicCredential::new(request.identity.to_vec()).into();

            // When the harness asks us to remove our prior appearance
            // (`remove_prior`), reuse the signing keypair of our existing leaf in
            // *this* group instead of minting a fresh one. Removing the prior leaf
            // by *identity* is the application's job -- OpenMLS does not interpret
            // credentials -- so OpenMLS offers only a convenience: its external
            // commit builder auto-adds the remove-prior proposal for a member whose
            // *signature key* matches ours. We opt into that convenience by reusing
            // our prior signing key, which is entirely our choice since we own it.
            // (Minting a fresh key would leave the old leaf in place, producing a
            // duplicate-identity tree that RFC-compliant peers such as mls-rs reject
            // with `DuplicateLeafData`.)
            //
            // We must find *our own* prior group, matching on both the group id and
            // our leaf identity: in self-interop both actors (e.g. alice and bob)
            // run on the same server, so several `InteropGroup`s share the same
            // group id. Matching on group id alone would pick the wrong actor's
            // group and reuse *their* signature key, which makes the remove-prior
            // target the wrong leaf (removing e.g. alice instead of our own prior
            // leaf).
            let group_id = verifiable_group_info.group_id().clone();
            let prior_signer = if request.remove_prior {
                let groups = self.groups();
                groups.iter().find_map(|g| {
                    let is_ours = g.group.group_id() == &group_id
                        && g.group
                            .own_leaf_node()
                            .is_some_and(|leaf| leaf.credential() == &credential);
                    is_ours.then(|| {
                        SignatureKeyPair::from_raw(
                            ciphersuite.signature_algorithm(),
                            g.signature_keys.private().to_vec(),
                            g.signature_keys.public().to_vec(),
                        )
                    })
                })
            } else {
                None
            };

            let (credential_with_key, signer) = {
                let signature_keypair = prior_signer.unwrap_or_else(|| {
                    SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap()
                });

                signature_keypair.store(provider.storage()).unwrap();

                let credential_with_key = CredentialWithKey {
                    credential: credential.clone(),
                    signature_key: signature_keypair.public().into(),
                };

                (credential_with_key, signature_keypair)
            };

            let mls_group_config = {
                let wire_format_policy = wire_format_policy(request.encrypt_handshake);

                MlsGroupJoinConfig::builder()
                    .max_past_epochs(32)
                    .number_of_resumption_psks(32)
                    .sender_ratchet_configuration(SenderRatchetConfiguration::default())
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(wire_format_policy)
                    .build()
            };

            let builder = MlsGroup::external_commit_builder().with_config(mls_group_config.clone());

            let (group, commit_bundle) = if let Some(tree_option) = ratchet_tree {
                builder.with_ratchet_tree(tree_option)
            } else {
                builder
            }
            .build_group(
                &provider,
                verifiable_group_info,
                credential_with_key.clone(),
            )
            .unwrap()
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &signer, |_| true)
            .unwrap()
            .finalize(&provider)
            .unwrap();

            let commit = commit_bundle.into_commit();
            trace!(?commit, "Commit created.");

            (
                InteropGroup {
                    wire_format_policy: mls_group_config.wire_format_policy(),
                    group,
                    signature_keys: signer,
                    messages_out: Vec::new(),
                    crypto_provider: provider,
                },
                commit,
            )
        };

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        let mut groups = self.groups();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = ExternalJoinResponse {
            state_id,
            commit: commit.tls_serialize_detached().unwrap(),
            epoch_authenticator,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn state_auth(
        &self,
        request: Request<StateAuthRequest>,
    ) -> Result<Response<StateAuthResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let groups = self.groups();
        let interop_group = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let state_auth_secret = interop_group.group.epoch_authenticator();

        let response = StateAuthResponse {
            state_auth_secret: state_auth_secret.as_slice().to_vec(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn export(
        &self,
        request: Request<ExportRequest>,
    ) -> Result<Response<ExportResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let groups = self.groups();
        let interop_group = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let exported_secret = interop_group
            .group
            .export_secret(
                interop_group.crypto_provider.crypto(),
                &request.label,
                &request.context,
                request.key_length as usize,
            )
            .map_err(into_status)?;

        let response = ExportResponse { exported_secret };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn protect(
        &self,
        request: Request<ProtectRequest>,
    ) -> Result<Response<ProtectResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;

        interop_group
            .group
            .set_aad(request.authenticated_data.clone());

        let ciphertext = interop_group
            .group
            .create_message(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                &request.plaintext,
            )
            .map_err(into_status)?
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize ciphertext"))?;

        let response = ProtectResponse { ciphertext };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn unprotect(
        &self,
        request: Request<UnprotectRequest>,
    ) -> Result<Response<UnprotectResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;

        debug!("Deserializing `MlsMessageIn`.");
        let message = MlsMessageIn::tls_deserialize(&mut request.ciphertext.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        debug!("Deserialized `MlsMessageIn`.");
        trace!(?message);

        debug!("Processing message.");
        let processed_message = interop_group
            .group
            .process_message(
                &interop_group.crypto_provider,
                message.try_into_protocol_message().unwrap(),
            )
            .map_err(into_status)?;
        debug!("Processed.");
        trace!(?processed_message);

        let authenticated_data = processed_message.aad().to_vec();
        let plaintext = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                application_message.into_bytes()
            }
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
            ProcessedMessageContent::OwnPendingCommit => unreachable!(),
            ProcessedMessageContent::OwnPrivateMessage => unreachable!(),
            // The `extensions-draft` feature has no interop scenarios, so an
            // AppData commit can never reach the client here.
            #[cfg(feature = "extensions-draft")]
            ProcessedMessageContent::UnresolvedAppDataCommit(_) => unreachable!(),
        };

        let response = UnprotectResponse {
            plaintext,
            authenticated_data,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn store_psk(
        &self,
        request: Request<StorePskRequest>,
    ) -> Result<Response<StorePskResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let raw_psk_id = request.psk_id.clone();
        trace!("   psk_id {:x?}", raw_psk_id);
        let external_psk = Psk::External(ExternalPsk::new(raw_psk_id));

        fn store(
            ciphersuite: Ciphersuite,
            crypto_provider: &OpenMlsRustCrypto,
            external_psk: Psk,
            secret: &[u8],
        ) -> Result<(), Status> {
            let psk_id = PreSharedKeyId::new(ciphersuite, crypto_provider.rand(), external_psk)
                .map_err(|_| Status::internal("unable to create PreSharedKeyId from raw psk_id"))?;
            psk_id
                .store(crypto_provider, secret)
                .map_err(|_| Status::new(Code::Internal, "unable to store PSK"))?;
            Ok(())
        }

        // This might be for a transaction ID or a state ID, so either a group, or not.
        // Transaction IDs are random. We assume that if it exists, it is what we want.
        let mut pending_state = self.pending_state();
        if let Some(pending_state) = pending_state.get_mut(&request.state_or_transaction_id) {
            store(
                pending_state.0.key_package().ciphersuite(),
                &pending_state.3,
                external_psk,
                &request.psk_secret,
            )?;
        } else {
            drop(pending_state);
            // So we have a group
            let mut groups = self.groups();
            let interop_group = groups
                .get_mut(request.state_or_transaction_id as usize)
                .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
            trace!("   in epoch {:?}", interop_group.group.epoch());

            store(
                interop_group.group.ciphersuite(),
                &interop_group.crypto_provider,
                external_psk,
                &request.psk_secret,
            )?;
        }

        let response = StorePskResponse::default();

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn add_proposal(
        &self,
        request: Request<AddProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let key_package = MlsMessageIn::tls_deserialize(&mut request.key_package.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize key package (MlsMessage)"))?
            .into_keypackage()
            .ok_or(Status::aborted("failed to deserialize key package"))?;
        trace!(
            "   for {:#x?}",
            key_package
                .hash_ref(interop_group.crypto_provider.crypto())
                .unwrap()
        );
        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group
            .group
            .set_configuration(interop_group.crypto_provider.storage(), &mls_group_config)
            .map_err(|err| {
                tonic::Status::internal(format!("error setting configuration: {err}"))
            })?;
        let (proposal, _) = interop_group
            .group
            .propose_add_member(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                &key_package,
            )
            .map_err(into_status)?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        let proposal = proposal.to_bytes().unwrap();

        let response = ProposalResponse { proposal };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn update_proposal(
        &self,
        request: Request<UpdateProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group
            .group
            .set_configuration(interop_group.crypto_provider.storage(), &mls_group_config)
            .map_err(|err| {
                tonic::Status::internal(format!("error setting configuration: {err}"))
            })?;
        let (proposal, _) = interop_group
            .group
            .propose_self_update(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                LeafNodeParameters::default(),
            )
            .map_err(into_status)?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        let proposal = proposal.to_bytes().unwrap();

        // XXX[FK]: Make sure the new keys are accessible?

        let response = ProposalResponse { proposal };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn remove_proposal(
        &self,
        request: Request<RemoveProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let removed_credential = BasicCredential::new(request.removed_id.clone());
        trace!("   for credential: {removed_credential:x?}");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group
            .group
            .set_configuration(interop_group.crypto_provider.storage(), &mls_group_config)
            .map_err(|err| {
                tonic::Status::internal(format!("error setting configuration: {err}"))
            })?;
        trace!("   prepared remove");

        let (proposal, _) = interop_group
            .group
            .propose_remove_member_by_credential(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                &removed_credential.into(),
            )
            .map_err(into_status)?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        let proposal = proposal.to_bytes().unwrap();
        trace!("   generated remove proposal");

        let response = ProposalResponse { proposal };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn re_init_proposal(
        &self,
        request: Request<ReInitProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;

        let ciphersuite = *to_ciphersuite(request.cipher_suite)?;
        let extensions = group_context_extensions_from_proto(&request.extensions)?;
        let reinit = ReInitProposal::new(
            GroupId::from_slice(&request.group_id),
            ProtocolVersion::Mls10,
            ciphersuite,
            extensions,
        );

        let (proposal, _proposal_ref) = interop_group
            .group
            .propose_reinit(
                &interop_group.crypto_provider,
                reinit,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;

        // Remember our own proposal so we skip re-processing it if it comes back
        // to us by reference.
        interop_group.messages_out.push(proposal.clone().into());

        let response = ProposalResponse {
            proposal: proposal
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize reinit proposal"))?,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        trace!(epoch=?group.epoch(), "Current group state.");

        // Proposals by reference. These proposals are standalone proposals. They should
        // be appended to the proposal store.
        for proposal in &request.by_reference {
            trace!("Handling proposal by reference.");

            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                trace!("Skipping processing of own proposal");
                continue;
            }
            trace!("Processing proposal ...");
            let processed_message = group
                .process_message(
                    &interop_group.crypto_provider,
                    message.try_into_protocol_message().unwrap(),
                )
                .map_err(into_status)?;
            trace!("... done");

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    group
                        .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                        .map_err(|err| {
                            tonic::Status::internal(format!("error storing proposal: {err}"))
                        })?;
                }
                // An external self-Add (`new_member_add_proposal`) committed by
                // reference: store it alongside regular proposals.
                ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                    group
                        .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                        .map_err(|err| {
                            tonic::Status::internal(format!(
                                "error storing external join proposal: {err}"
                            ))
                        })?;
                }
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
                ProcessedMessageContent::OwnPendingCommit => unreachable!(),
                // A referenced proposal we authored ourselves comes back as our
                // own PrivateMessage; the content can't be decrypted and it is
                // already in our proposal store, so we skip it.
                ProcessedMessageContent::OwnPrivateMessage => {
                    trace!("Skipping own private message (proposal by reference)");
                }
                // The `extensions-draft` feature has no interop scenarios, so an
                // AppData commit can never reach the client here.
                #[cfg(feature = "extensions-draft")]
                ProcessedMessageContent::UnresolvedAppDataCommit(_) => unreachable!(),
            }
        }

        // Proposals by value. These proposals are inline proposals. They should be
        // converted into group operations.
        for proposal in &request.by_value {
            let proposal_type = String::from_utf8_lossy(&proposal.proposal_type).to_string();
            trace!(r#type = proposal_type, "Handling proposal by value.");

            // build the proposal from the raw values in proposal
            let (proposal, _proposal_ref) = match proposal_type.as_ref() {
                "add" => {
                    let key_package =
                        MlsMessageIn::tls_deserialize_exact(proposal.key_package.clone())
                            .map_err(|_| Status::invalid_argument("Invalid key package"))?;
                    let key_package = key_package
                        .into_keypackage()
                        .ok_or(Status::invalid_argument("Message was not a key package"))?;

                    group
                        .propose_add_member_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            key_package,
                        )
                        .map_err(|_| Status::internal("Unable to generate proposal by value"))?
                }
                "remove" => {
                    let removed_credential = BasicCredential::new(proposal.removed_id.clone());

                    group
                        .propose_remove_member_by_credential_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            &removed_credential.into(),
                        )
                        .map_err(|_| Status::internal("Unable to generate proposal by value"))?
                }
                "externalPSK" => {
                    let psk_id = PreSharedKeyId::new(
                        group.ciphersuite(),
                        interop_group.crypto_provider.rand(),
                        Psk::External(ExternalPsk::new(proposal.psk_id.clone())),
                    )
                    .map_err(|_| Status::internal("Unsupported proposal type (resumption PSK)"))?;

                    group
                        .propose_pre_shared_key_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            psk_id,
                        )
                        .map_err(|_| Status::internal("Unable to generate proposal by value"))?
                }
                "resumptionPSK" => {
                    let psk_nonce = interop_group
                        .crypto_provider
                        .rand()
                        .random_vec(group.ciphersuite().hash_length())
                        .map_err(|_| Status::internal("insufficient randomness for psk nonce"))?;
                    let psk_id = PreSharedKeyId::resumption(
                        ResumptionPskUsage::Application,
                        group.group_id().clone(),
                        GroupEpoch::from(proposal.epoch_id),
                        psk_nonce,
                    );

                    // TODO: epoch_id vs epoch?
                    let (msg_out, proposal_ref) = group
                        .propose_pre_shared_key_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            psk_id,
                        )
                        .map_err(into_status)?;
                    debug!("Resumption PSK proposal created.");
                    trace!(proposal = ?msg_out);
                    trace!(proposal_ref = ?proposal_ref);

                    (msg_out, proposal_ref)
                }
                "groupContextExtensions" => {
                    let extensions = group_context_extensions_from_proto(&proposal.extensions)?;
                    group
                        .propose(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            Propose::GroupContextExtensions(extensions),
                            ProposalOrRefType::Proposal,
                        )
                        .map_err(into_status)?
                }
                _ => return Err(Status::invalid_argument("Invalid proposal type")),
            };

            let message: MlsMessageIn = proposal.into();
            if interop_group.messages_out.contains(&message) {
                trace!("   skipping processing of own proposal");
                continue;
            }
        }

        // TODO #692: The interop client cannot process these proposals yet.

        let (commit, welcome_option, _group_info) = group
            .commit_to_pending_proposals(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;

        let commit = commit.to_bytes().unwrap();

        let welcome = if let Some(welcome) = welcome_option {
            welcome
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize welcome"))?
        } else {
            vec![]
        };

        debug!(commit=?group.pending_commit(), "Pending commit created. (Note: Not merged yet.)");

        group
            .merge_pending_commit(&interop_group.crypto_provider)
            .map_err(into_status)?;

        debug!("Merged pending commit.");

        let ratchet_tree = if request.external_tree {
            group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize ratchet tree"))?
        } else {
            vec![]
        };

        let response = CommitResponse {
            commit,
            welcome,
            ratchet_tree,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn handle_commit(
        &self,
        request: Request<HandleCommitRequest>,
    ) -> Result<Response<HandleCommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        trace!(epoch=?group.epoch(), "Current group state.");

        // XXX[FK]: This is a horrible API.

        for proposal in &request.proposal {
            // trace!("   proposals by reference ... we don't care.");
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                trace!("   skipping processing of own proposal");
                continue;
            }
            trace!("   processing proposal ...");
            let processed_message = group
                .process_message(
                    &interop_group.crypto_provider,
                    message.try_into_protocol_message().unwrap(),
                )
                .map_err(into_status)?;
            trace!("       done");
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    group
                        .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                        .map_err(|err| {
                            tonic::Status::internal(format!(
                                "error storing pending proposal: {err}"
                            ))
                        })?;
                }
                // An external self-Add (`new_member_add_proposal`) committed by
                // reference: store it alongside regular proposals.
                ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                    group
                        .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                        .map_err(|err| {
                            tonic::Status::internal(format!(
                                "error storing external join proposal: {err}"
                            ))
                        })?;
                }
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
                ProcessedMessageContent::OwnPendingCommit => unreachable!(),
                // A referenced proposal we authored ourselves comes back as our
                // own PrivateMessage; the content can't be decrypted and it is
                // already in our proposal store, so we skip it.
                ProcessedMessageContent::OwnPrivateMessage => {
                    trace!("Skipping own private message (proposal by reference)");
                }
                // The `extensions-draft` feature has no interop scenarios, so an
                // AppData commit can never reach the client here.
                #[cfg(feature = "extensions-draft")]
                ProcessedMessageContent::UnresolvedAppDataCommit(_) => unreachable!(),
            }
        }

        debug!("Deserializing `MlsMessageIn`.");
        let message =
            MlsMessageIn::tls_deserialize(&mut request.commit.as_slice()).map_err(|_| {
                error!("Failed to deserialize ciphertext");
                Status::aborted("failed to deserialize ciphertext")
            })?;
        debug!("Deserialized.");
        trace!(?message);

        debug!("Processing message.");
        let processed_message = group
            .process_message(
                &interop_group.crypto_provider,
                message.try_into_protocol_message().unwrap(),
            )
            .map_err(into_status)?;
        debug!("Processed.");
        trace!(?processed_message);

        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                debug!(commit=?staged_commit, "Merging staged commit.");
                group
                    .merge_staged_commit(&interop_group.crypto_provider, *staged_commit)
                    .map_err(into_status)?;
            }
            ProcessedMessageContent::OwnPendingCommit => unreachable!(),
            ProcessedMessageContent::OwnPrivateMessage => unreachable!(),
            // The `extensions-draft` feature has no interop scenarios, so an
            // AppData commit can never reach the client here.
            #[cfg(feature = "extensions-draft")]
            ProcessedMessageContent::UnresolvedAppDataCommit(_) => unreachable!(),
        }

        trace!(epoch=?group.epoch(), "New group state.");

        let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();

        let response = HandleCommitResponse {
            state_id: request.state_id,
            epoch_authenticator,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn handle_pending_commit(
        &self,
        request: Request<HandlePendingCommitRequest>,
    ) -> Result<Response<HandleCommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        trace!(epoch=?group.epoch(), "Current group state.");

        trace!(commit=?group.pending_commit(), "Merging pending commit.");
        group
            .merge_pending_commit(&interop_group.crypto_provider)
            .map_err(|e| {
                trace!("Error merging pending commit: `{e:?}`");
                Status::aborted("failed to apply pending commits")
            })?;
        trace!(epoch=?group.epoch(), "New group state.");

        let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();
        let response = HandleCommitResponse {
            state_id: request.state_id,
            epoch_authenticator,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn group_info(
        &self,
        request: Request<GroupInfoRequest>,
    ) -> Result<Response<GroupInfoResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        let group_info = group
            .export_group_info(
                interop_group.crypto_provider.crypto(),
                &interop_group.signature_keys,
                !request.external_tree,
            )
            .unwrap();
        debug!("Group info exported.");
        trace!(?group_info);

        let ratchet_tree = if request.external_tree {
            group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| Status::internal("Unable to serialize ratchet tree."))?
        } else {
            vec![]
        };

        let response = GroupInfoResponse {
            group_info: group_info.tls_serialize_detached().unwrap(),
            ratchet_tree,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn external_psk_proposal(
        &self,
        request: Request<ExternalPskProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let raw_psk_id = request.psk_id.clone();
        trace!("   psk_id {:x?}", raw_psk_id);
        let external_psk = Psk::External(ExternalPsk::new(raw_psk_id));

        let psk_id = PreSharedKeyId::new(
            interop_group.group.ciphersuite(),
            interop_group.crypto_provider.rand(),
            external_psk,
        )
        .map_err(|_| Status::internal("unable to create PreSharedKeyId from raw psk_id"))?;

        let (proposal, _proposal_ref) = interop_group
            .group
            .propose_pre_shared_key(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                psk_id,
            )
            .map_err(|_| Status::internal("failed to generate psk proposal"))?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        // trace!("   proposal: {proposal:#x?}");
        let proposal = proposal.to_bytes().unwrap();

        let response = ProposalResponse { proposal };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn resumption_psk_proposal(
        &self,
        request: Request<ResumptionPskProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        let psk_nonce = interop_group
            .crypto_provider
            .rand()
            .random_vec(group.ciphersuite().hash_length())
            .map_err(|_| Status::internal("insufficient randomness for psk nonce"))?;
        let psk_id = PreSharedKeyId::resumption(
            ResumptionPskUsage::Application,
            group.group_id().clone(),
            GroupEpoch::from(request.epoch_id),
            psk_nonce,
        );

        let (msg_out, _proposal_ref) = interop_group
            .group
            .propose_pre_shared_key(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                psk_id,
            )
            .map_err(into_status)?;
        debug!("Resumption PSK proposal created.");
        trace!(proposal = ?msg_out);

        // Record our own proposal so that, when we later commit to it by
        // reference, we skip re-processing it. Without this the proposal is
        // processed again and ends up folded into the PSK secret twice, which
        // desyncs our confirmation tag from the emitted commit. Matches every
        // other proposal RPC.
        interop_group.messages_out.push(msg_out.clone().into());

        let response = ProposalResponse {
            proposal: msg_out.tls_serialize_detached().unwrap(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn group_context_extensions_proposal(
        &self,
        request: Request<GroupContextExtensionsProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let extensions = group_context_extensions_from_proto(&request.extensions)?;

        // Note: We just use some values here that make live testing work.
        //       There is nothing special about the used numbers and they
        //       can be increased (or decreased) depending on the available scenarios.
        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group
            .group
            .set_configuration(interop_group.crypto_provider.storage(), &mls_group_config)
            .map_err(|err| {
                tonic::Status::internal(format!("error setting configuration: {err}"))
            })?;

        let (proposal, _) = interop_group
            .group
            .propose_group_context_extensions(
                &interop_group.crypto_provider,
                extensions,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        let proposal = proposal.to_bytes().unwrap();

        let response = ProposalResponse { proposal };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    // ReInit is not implemented in OpenMLS. Return a clean `Unimplemented` status
    // (rather than `todo!()`, which panics the handler and tears down the stream
    // as an ambiguous RST_STREAM CANCEL) so the interop runner reports these as
    // unsupported rather than as crashes.
    // Reinitialization (RFC 9420 §11.2). The old group is committed with a
    // single ReInit proposal (`re_init_commit`), which suspends it once merged
    // (`handle_pending_re_init_commit` for the committer,
    // `handle_re_init_commit` for the others). Each member then mints a fresh
    // key package for the successor group and gets a `reinit_id` handle. The
    // welcomer creates the successor group (`re_init_welcome`, mirroring
    // `create_branch` but with `CommitBuilder::reinit`); everyone else joins it
    // (`handle_re_init_welcome`, mirroring `handle_branch` with
    // `StagedWelcome::new_from_reinit`).

    #[instrument(skip_all)]
    async fn re_init_commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        // The ReInit proposal is committed by reference (the runner only
        // supports by-reference for ReInit): process and store it.
        for proposal in &request.by_reference {
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                continue;
            }
            let processed_message = group
                .process_message(
                    &interop_group.crypto_provider,
                    message.try_into_protocol_message().unwrap(),
                )
                .map_err(into_status)?;
            match processed_message.into_content() {
                ProcessedMessageContent::ProposalMessage(proposal) => group
                    .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                    .map_err(|err| {
                        Status::internal(format!("error storing reinit proposal: {err}"))
                    })?,
                ProcessedMessageContent::OwnPrivateMessage => {}
                other => {
                    return Err(Status::aborted(format!(
                        "unexpected message while committing reinit: {other:?}"
                    )))
                }
            }
        }

        // Build and stage the ReInit commit, but do NOT merge it yet: the
        // committer advances its state in `handle_pending_re_init_commit`.
        let (commit, _welcome, _group_info) = group
            .commit_to_pending_proposals(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;

        let response = CommitResponse {
            commit: commit
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize reinit commit"))?,
            // A ReInit commit contains no Add proposals and therefore no Welcome.
            welcome: vec![],
            ratchet_tree: vec![],
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn handle_pending_re_init_commit(
        &self,
        request: Request<HandlePendingCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;

        // Capture the committed ReInit proposal from the pending commit before
        // merging (merging consumes it and suspends the group).
        let reinit_proposal = interop_group
            .group
            .pending_commit()
            .and_then(|staged| staged.reinit_proposal().cloned())
            .ok_or_else(|| Status::internal("pending commit does not contain a ReInit proposal"))?;

        // Merging the committer's own pending ReInit commit suspends the group.
        interop_group
            .group
            .merge_pending_commit(&interop_group.crypto_provider)
            .map_err(into_status)?;

        let response = self.build_reinit_state(interop_group, request.state_id, reinit_proposal)?;
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn handle_re_init_commit(
        &self,
        request: Request<HandleCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        // Process and store the referenced ReInit proposal(s).
        for proposal in &request.proposal {
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                continue;
            }
            let processed_message = group
                .process_message(
                    &interop_group.crypto_provider,
                    message.try_into_protocol_message().unwrap(),
                )
                .map_err(into_status)?;
            match processed_message.into_content() {
                ProcessedMessageContent::ProposalMessage(proposal) => group
                    .store_pending_proposal(interop_group.crypto_provider.storage(), *proposal)
                    .map_err(|err| {
                        Status::internal(format!("error storing reinit proposal: {err}"))
                    })?,
                ProcessedMessageContent::OwnPrivateMessage => {}
                other => {
                    return Err(Status::aborted(format!(
                        "unexpected proposal message in reinit commit: {other:?}"
                    )))
                }
            }
        }

        // Process and merge the ReInit commit, suspending the group.
        let message = MlsMessageIn::tls_deserialize(&mut request.commit.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize reinit commit"))?;
        let processed_message = group
            .process_message(
                &interop_group.crypto_provider,
                message.try_into_protocol_message().unwrap(),
            )
            .map_err(into_status)?;
        let reinit_proposal = match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // Capture the committed ReInit proposal before merging consumes
                // the staged commit.
                let reinit_proposal =
                    staged_commit.reinit_proposal().cloned().ok_or_else(|| {
                        Status::aborted("reinit commit does not contain a ReInit proposal")
                    })?;
                group
                    .merge_staged_commit(&interop_group.crypto_provider, *staged_commit)
                    .map_err(into_status)?;
                reinit_proposal
            }
            other => {
                return Err(Status::aborted(format!(
                    "expected a staged reinit commit, got {other:?}"
                )))
            }
        };

        let response = self.build_reinit_state(interop_group, request.state_id, reinit_proposal)?;
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn re_init_welcome(
        &self,
        request: Request<ReInitWelcomeRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        // Take our reinit state (fresh provider + successor signer/credential).
        let reinit_state = self
            .pending_reinits()
            .remove(&request.reinit_id)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown reinit_id"))?;
        let ReInitState {
            old_state_id,
            crypto_provider,
            signature_keys,
            credential,
            key_package: _,
            wire_format_policy,
            reinit_proposal,
        } = reinit_state;

        // Key packages of the other successor members.
        let key_packages = request
            .key_package
            .iter()
            .map(|kp| {
                let msg = MlsMessageIn::tls_deserialize_exact(kp.clone())
                    .map_err(|_| Status::invalid_argument("Invalid key package"))?;
                msg.into_keypackage()
                    .ok_or_else(|| Status::invalid_argument("Message was not a key package"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut groups = self.groups();
        let old_group = &groups
            .get(old_state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown reinit old state_id"))?
            .group;

        // Create the successor group with the ReInit parameters.
        let mut successor = MlsGroup::builder()
            .with_group_id(reinit_proposal.group_id().clone())
            .ciphersuite(reinit_proposal.ciphersuite())
            .with_group_context_extensions(reinit_proposal.extensions().clone())
            .use_ratchet_tree_extension(true)
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .with_wire_format_policy(wire_format_policy)
            .build(&crypto_provider, &signature_keys, credential.clone())
            .map_err(into_status)?;

        // Build the reinit commit that adds the other members and mixes in the
        // old group's resumption PSK (usage `Reinit`).
        let mut builder = successor
            .commit_builder()
            .reinit(crypto_provider.rand(), old_group)
            .map_err(into_status)?
            .propose_adds(key_packages);
        if request.force_path {
            builder = builder.force_self_update(true);
        }
        let bundle = builder
            .load_psks(crypto_provider.storage())
            .map_err(into_status)?
            .build(
                crypto_provider.rand(),
                crypto_provider.crypto(),
                &signature_keys,
                |_| true,
            )
            .map_err(into_status)?
            .stage_commit(&crypto_provider)
            .map_err(into_status)?;

        let welcome = MlsMessageOut::from_welcome(
            bundle
                .welcome()
                .ok_or_else(|| Status::internal("reinit commit produced no welcome"))?
                .clone(),
            ProtocolVersion::Mls10,
        )
        .tls_serialize_detached()
        .map_err(|_| Status::aborted("failed to serialize welcome"))?;

        successor
            .merge_pending_commit(&crypto_provider)
            .map_err(into_status)?;

        let ratchet_tree = if request.external_tree {
            successor
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize ratchet tree"))?
        } else {
            vec![]
        };
        let epoch_authenticator = successor.epoch_authenticator().as_slice().to_vec();

        let interop_group = InteropGroup {
            group: successor,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = CreateSubgroupResponse {
            state_id,
            welcome,
            ratchet_tree,
            epoch_authenticator,
        };
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn handle_re_init_welcome(
        &self,
        request: Request<HandleReInitWelcomeRequest>,
    ) -> Result<Response<JoinGroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let reinit_state = self
            .pending_reinits()
            .remove(&request.reinit_id)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown reinit_id"))?;
        let ReInitState {
            old_state_id,
            crypto_provider,
            signature_keys,
            credential: _,
            key_package,
            wire_format_policy,
            reinit_proposal,
        } = reinit_state;

        use openmls_traits::storage::StorageProvider as _;

        // Store our freshly minted successor key package so the Welcome can be
        // resolved against it (mirrors `handle_branch`).
        crypto_provider
            .storage()
            .write_key_package(
                &key_package
                    .key_package()
                    .hash_ref(crypto_provider.crypto())
                    .map_err(into_status)?,
                &key_package,
            )
            .map_err(into_status)?;

        let welcome = MlsMessageIn::tls_deserialize(&mut request.welcome.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize welcome"))?
            .into_welcome()
            .ok_or_else(|| Status::aborted("expected a welcome message"))?;
        let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

        let mut groups = self.groups();
        let old_group = &groups
            .get(old_state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown reinit old state_id"))?
            .group;

        let join_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();

        let group = StagedWelcome::new_from_reinit(
            &crypto_provider,
            &join_config,
            welcome,
            ratchet_tree,
            old_group,
            &reinit_proposal,
            true,
        )
        .map_err(into_status)?
        .into_group(&crypto_provider)
        .map_err(into_status)?;

        let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();

        let interop_group = InteropGroup {
            group,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = JoinGroupResponse {
            state_id,
            epoch_authenticator,
        };
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    // Subgroup branching (RFC 9420 §11.3): a subset of an existing group's
    // members forms a new group, mixing the parent's resumption PSK (usage
    // `Branch`) into the new group's key schedule. `create_branch` is the creator
    // side (mirrors `create_group` + `commit`); `handle_branch` is the joiner side
    // (mirrors `join_group`, with `new_from_welcome` swapped for `new_from_branch`).
    #[instrument(skip_all)]
    async fn create_branch(
        &self,
        request: Request<CreateBranchRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let parent = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;

        trace!(epoch=?parent.group.epoch(), "Parent group state.");

        // The subgroup reuses the parent member's credential + signing key and
        // must match the parent's ciphersuite / wire-format policy.
        let ciphersuite = parent.group.ciphersuite();
        let credential = parent.group.credential().map_err(into_status)?.clone();
        // `SignatureKeyPair` is not `Clone` here (the `clonable` feature is off),
        // so reconstruct it from the raw key material.
        let signature_keys = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            parent.signature_keys.private().to_vec(),
            parent.signature_keys.public().to_vec(),
        );
        let wire_format_policy = parent.wire_format_policy;

        // A fresh provider is sufficient: `branch()` injects the parent's
        // resumption-PSK secret (cloned in-memory), so no shared storage with the
        // parent is needed. Store the signing keys for the subgroup's operations.
        let provider = OpenMlsRustCrypto::default();
        signature_keys
            .store(provider.storage())
            .map_err(into_status)?;

        let mls_group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();

        let mut sub_group = MlsGroup::new_with_group_id(
            &provider,
            &signature_keys,
            &mls_group_config,
            GroupId::from_slice(&request.group_id),
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(into_status)?;

        // Members to add to the subgroup. Each key package arrives as an
        // MlsMessage-wrapped KeyPackage, like the `commit` handler's "add" branch.
        let key_packages = request
            .key_packages
            .iter()
            .map(|kp| {
                let msg = MlsMessageIn::tls_deserialize_exact(kp.clone())
                    .map_err(|_| Status::invalid_argument("Invalid key package"))?;
                msg.into_keypackage()
                    .ok_or_else(|| Status::invalid_argument("Message was not a key package"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Build the branch commit. `branch()` mixes in the parent's resumption PSK
        // and borrows the parent only for this call (it does not retain the ref).
        let mut builder = sub_group
            .commit_builder()
            .branch(provider.rand(), &parent.group)
            .map_err(into_status)?
            .propose_adds(key_packages);
        if !request.extensions.is_empty() {
            let extensions = group_context_extensions_from_proto(&request.extensions)?;
            builder = builder
                .propose_group_context_extensions(extensions)
                .map_err(into_status)?;
        }
        if request.force_path {
            builder = builder.force_self_update(true);
        }
        let bundle = builder
            .load_psks(provider.storage())
            .map_err(into_status)?
            .build(provider.rand(), provider.crypto(), &signature_keys, |_| {
                true
            })
            .map_err(into_status)?
            .stage_commit(&provider)
            .map_err(into_status)?;

        let welcome = MlsMessageOut::from_welcome(
            bundle
                .welcome()
                .ok_or_else(|| Status::internal("branch commit produced no welcome"))?
                .clone(),
            ProtocolVersion::Mls10,
        )
        .tls_serialize_detached()
        .map_err(|_| Status::aborted("failed to serialize welcome"))?;

        sub_group
            .merge_pending_commit(&provider)
            .map_err(into_status)?;

        let ratchet_tree = if request.external_tree {
            sub_group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize ratchet tree"))?
        } else {
            vec![]
        };

        let epoch_authenticator = sub_group.epoch_authenticator().as_slice().to_vec();

        let interop_group = InteropGroup {
            group: sub_group,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider: provider,
        };

        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = CreateSubgroupResponse {
            state_id,
            welcome,
            ratchet_tree,
            epoch_authenticator,
        };
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn handle_branch(
        &self,
        request: Request<HandleBranchRequest>,
    ) -> Result<Response<HandleBranchResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        // Pick up the joiner's pending key package (minted via `create_key_package`
        // and keyed by transaction id), exactly like `join_group`.
        let (my_key_package, _my_credential, my_signature_keys, crypto_provider) = self
            .pending_state()
            .remove(&request.transaction_id)
            .ok_or(Status::aborted(format!(
                "failed to find key package for transaction id {}",
                request.transaction_id
            )))?;

        use openmls_traits::storage::StorageProvider as _;

        // Store the key package in the key store with the hash reference as id for
        // retrieval when parsing the (branch) welcome message.
        crypto_provider
            .storage()
            .write_key_package(
                &my_key_package
                    .key_package()
                    .hash_ref(crypto_provider.crypto())
                    .map_err(into_status)?,
                &my_key_package,
            )
            .map_err(into_status)?;

        let welcome = MlsMessageIn::tls_deserialize(&mut request.welcome.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize MlsMessage with a Welcome"))?
            .into_welcome()
            .expect("expected a welcome");

        let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

        let mut groups = self.groups();
        let parent = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let wire_format_policy = parent.wire_format_policy;

        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();

        // `new_from_branch` injects the parent's resumption-PSK secret and enforces
        // the RFC §11.3 receiver checks. `check_members = true`: the runner re-mints
        // key packages with the same BasicCredential identities, so the
        // credential-equality check passes. It borrows the parent only until
        // `into_group` yields an owned group.
        let group = StagedWelcome::new_from_branch(
            &crypto_provider,
            &mls_group_config,
            welcome,
            ratchet_tree,
            &parent.group,
            true,
        )
        .map_err(into_status)?
        .into_group(&crypto_provider)
        .map_err(into_status)?;

        let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();

        let interop_group = InteropGroup {
            group,
            wire_format_policy,
            signature_keys: my_signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };

        let state_id = groups.len() as u32;
        groups.push(interop_group);

        let response = HandleBranchResponse {
            state_id,
            epoch_authenticator,
        };
        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn new_member_add_proposal(
        &self,
        request: Request<NewMemberAddProposalRequest>,
    ) -> Result<Response<NewMemberAddProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        Span::current().record("actor", bytes_to_string(&request.identity));

        // Learn the group we want to join from the provided GroupInfo.
        let verifiable_group_info = {
            let msg = MlsMessageIn::tls_deserialize(&mut request.group_info.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize group info (MlsMessage)"))?;
            match msg.extract() {
                MlsMessageBodyIn::GroupInfo(verifiable_group_info) => verifiable_group_info,
                other => {
                    return Err(Status::aborted(format!(
                        "expected MlsMessageBodyIn::GroupInfo, got {other:?}"
                    )))
                }
            }
        };
        let ciphersuite = verifiable_group_info.ciphersuite();
        let group_id = verifiable_group_info.group_id().clone();
        let epoch = verifiable_group_info.epoch();

        // Create a fresh identity + key package for the joiner, mirroring
        // `create_key_package` so the eventual `join_group` (driven by the
        // fullCommit's welcome) can pick up the private material.
        let crypto_provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(request.identity.clone());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|_| Status::internal("failed to create signature keys"))?;

        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(Capabilities::new(
                Some(&[ProtocolVersion::Mls10, ProtocolVersion::Other(999)]),
                Some(&[
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ]),
                // See the note in `create_key_package`: default extension types
                // must not be listed here, and we support no non-default ones.
                None,
                None,
                Some(&CREDENTIAL_TYPES),
            ))
            .build(
                ciphersuite,
                &crypto_provider,
                &signature_keys,
                CredentialWithKey {
                    credential: credential.clone().into(),
                    signature_key: signature_keys.public().into(),
                },
            )
            .map_err(into_status)?;

        // Build the external (self-signed) Add proposal.
        let proposal =
            JoinProposal::new::<<OpenMlsRustCrypto as OpenMlsProvider>::StorageProvider>(
                key_package.key_package().clone(),
                group_id,
                epoch,
                &signature_keys,
            )
            .map_err(into_status)?;

        let transaction_id: [u8; 4] = crypto_provider
            .rand()
            .random_array()
            .map_err(|_| Status::internal("insufficient randomness for transaction id"))?;
        let transaction_id = u32::from_be_bytes(transaction_id);

        let response = NewMemberAddProposalResponse {
            transaction_id,
            proposal: proposal
                .tls_serialize_detached()
                .map_err(|_| Status::internal("error serializing proposal"))?,
            encryption_priv: key_package
                .encryption_private_key()
                .tls_serialize_detached()
                .unwrap(),
            init_priv: key_package
                .init_private_key()
                .tls_serialize_detached()
                .unwrap(),
            signature_priv: signature_keys.private().to_vec(),
        };

        self.pending_state().insert(
            transaction_id,
            (
                key_package,
                credential.into(),
                signature_keys,
                crypto_provider,
            ),
        );

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn create_external_signer(
        &self,
        request: Request<CreateExternalSignerRequest>,
    ) -> Result<Response<CreateExternalSignerResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        Span::current().record("actor", bytes_to_string(&request.identity));

        let ciphersuite = *to_ciphersuite(request.cipher_suite)?;
        let credential = BasicCredential::new(request.identity.clone());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|_| Status::internal("failed to create signature keys"))?;

        // The `ExternalSender` is what group members embed in their
        // `ExternalSenders` group context extension to authorize this signer.
        let external_sender =
            ExternalSender::new(signature_keys.public().into(), credential.clone().into());
        let external_sender = external_sender
            .tls_serialize_detached()
            .map_err(|_| Status::internal("error serializing external sender"))?;

        // Mint a signer id that `external_signer_proposal` uses to find the key.
        let crypto_provider = OpenMlsRustCrypto::default();
        let signer_id: [u8; 4] = crypto_provider
            .rand()
            .random_array()
            .map_err(|_| Status::internal("insufficient randomness for signer id"))?;
        let signer_id = u32::from_be_bytes(signer_id);

        self.external_signers()
            .insert(signer_id, (signature_keys, credential.into()));

        let response = CreateExternalSignerResponse {
            signer_id,
            external_sender,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn add_external_signer(
        &self,
        request: Request<AddExternalSignerRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());

        let external_sender =
            ExternalSender::tls_deserialize(&mut request.external_sender.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize external sender"))?;

        // Append to any existing external senders so we don't drop previously
        // added signers (e.g. the `multiple_external` scenario).
        let mut external_senders = interop_group
            .group
            .extensions()
            .external_senders()
            .cloned()
            .unwrap_or_default();
        external_senders.push(external_sender);
        let extensions = Extensions::single(Extension::ExternalSenders(external_senders))
            .map_err(|err| Status::aborted(format!("invalid external senders extension: {err}")))?;

        let mls_group_config = MlsGroupJoinConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group
            .group
            .set_configuration(interop_group.crypto_provider.storage(), &mls_group_config)
            .map_err(|err| {
                tonic::Status::internal(format!("error setting configuration: {err}"))
            })?;

        let (proposal, _) = interop_group
            .group
            .propose_group_context_extensions(
                &interop_group.crypto_provider,
                extensions,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;

        // Store the proposal so the committer's by-reference loop skips it.
        interop_group.messages_out.push(proposal.clone().into());

        let response = ProposalResponse {
            proposal: proposal.to_bytes().unwrap(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn external_signer_proposal(
        &self,
        request: Request<ExternalSignerProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        // Find the signer we minted in `create_external_signer`.
        let signers = self.external_signers();
        let (signature_keys, _credential) = signers
            .get(&request.signer_id)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown signer_id"))?;

        // The external signer is not a member; it works off the provided
        // GroupInfo (+ ratchet tree for removes).
        let verifiable_group_info = {
            let msg = MlsMessageIn::tls_deserialize(&mut request.group_info.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize group info (MlsMessage)"))?;
            match msg.extract() {
                MlsMessageBodyIn::GroupInfo(verifiable_group_info) => verifiable_group_info,
                other => {
                    return Err(Status::aborted(format!(
                        "expected MlsMessageBodyIn::GroupInfo, got {other:?}"
                    )))
                }
            }
        };
        let group_id = verifiable_group_info.group_id().clone();
        let epoch = verifiable_group_info.epoch();
        let sender_index = SenderExtensionIndex::new(request.signer_index);

        let description = request
            .description
            .as_ref()
            .ok_or_else(|| Status::aborted("missing proposal description"))?;
        let proposal_type = String::from_utf8_lossy(&description.proposal_type).to_string();

        let proposal: MlsMessageOut = match proposal_type.as_str() {
            "add" => {
                let key_package =
                    MlsMessageIn::tls_deserialize(&mut description.key_package.as_slice())
                        .map_err(|_| {
                            Status::aborted("failed to deserialize key package (MlsMessage)")
                        })?
                        .into_keypackage()
                        .ok_or(Status::aborted("failed to deserialize key package"))?;
                ExternalProposal::new_add::<OpenMlsRustCrypto>(
                    key_package,
                    group_id,
                    epoch,
                    signature_keys,
                    sender_index,
                )
                .map_err(into_status)?
            }
            "remove" => {
                // Map the removed identity to a leaf index using the ratchet tree.
                let ratchet_tree =
                    RatchetTreeIn::tls_deserialize(&mut request.ratchet_tree.as_slice())
                        .map_err(|_| Status::aborted("failed to deserialize ratchet tree"))?;
                let removed_credential: Credential =
                    BasicCredential::new(description.removed_id.clone()).into();
                let leaf_index = ratchet_tree
                    .leaves()
                    .enumerate()
                    .find(|(_, leaf)| leaf.credential() == &removed_credential)
                    .map(|(i, _)| LeafNodeIndex::new(i as u32))
                    .ok_or_else(|| Status::aborted("removed member not found in ratchet tree"))?;
                ExternalProposal::new_remove::<OpenMlsRustCrypto>(
                    leaf_index,
                    group_id,
                    epoch,
                    signature_keys,
                    sender_index,
                )
                .map_err(into_status)?
            }
            "groupContextExtensions" => {
                let extensions = group_context_extensions_from_proto(&description.extensions)?;
                ExternalProposal::new_group_context_extensions::<OpenMlsRustCrypto>(
                    extensions,
                    group_id,
                    epoch,
                    signature_keys,
                    sender_index,
                )
                .map_err(into_status)?
            }
            "externalPSK" => {
                // RFC 9420 §12.1.8.2 permits external senders to send PSK proposals.
                let provider = OpenMlsRustCrypto::default();
                let psk_id = PreSharedKeyId::new(
                    verifiable_group_info.ciphersuite(),
                    provider.rand(),
                    Psk::External(ExternalPsk::new(description.psk_id.clone())),
                )
                .map_err(|_| Status::internal("unable to create external PreSharedKeyId"))?;
                ExternalProposal::new_pre_shared_key(
                    psk_id,
                    group_id,
                    epoch,
                    signature_keys,
                    sender_index,
                )
                .map_err(into_status)?
            }
            "resumptionPSK" => {
                let provider = OpenMlsRustCrypto::default();
                let psk_nonce = provider
                    .rand()
                    .random_vec(verifiable_group_info.ciphersuite().hash_length())
                    .map_err(|_| Status::internal("insufficient randomness for psk nonce"))?;
                let psk_id = PreSharedKeyId::resumption(
                    ResumptionPskUsage::Application,
                    group_id.clone(),
                    GroupEpoch::from(description.epoch_id),
                    psk_nonce,
                );
                ExternalProposal::new_pre_shared_key(
                    psk_id,
                    group_id,
                    epoch,
                    signature_keys,
                    sender_index,
                )
                .map_err(into_status)?
            }
            "reinit" => {
                // RFC 9420 §12.1.8.2 permits external senders to send ReInit
                // proposals. The description carries the *successor* group's
                // parameters; the old group id/epoch come from the group info.
                let ciphersuite = *to_ciphersuite(description.cipher_suite)?;
                let extensions = group_context_extensions_from_proto(&description.extensions)?;
                let reinit = ReInitProposal::new(
                    GroupId::from_slice(&description.group_id),
                    ProtocolVersion::Mls10,
                    ciphersuite,
                    extensions,
                );
                ExternalProposal::new_reinit(reinit, group_id, epoch, signature_keys, sender_index)
                    .map_err(into_status)?
            }
            other => {
                return Err(Status::unimplemented(format!(
                    "external sender {other} proposals are not supported by OpenMLS"
                )))
            }
        };

        let response = ProposalResponse {
            proposal: proposal
                .tls_serialize_detached()
                .map_err(|_| Status::internal("error serializing proposal"))?,
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    async fn free(&self, _request: Request<FreeRequest>) -> Result<Response<FreeResponse>, Status> {
        debug!("Got Free request");
        let response = FreeResponse {};
        Ok(Response::new(response))
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(long, default_value = "0.0.0.0")]
    host: String,

    #[clap(short, long, default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .init();

    let opts = Opts::parse();
    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::new();

    info!(%addr, "Listening");

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
