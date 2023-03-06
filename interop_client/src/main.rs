//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client in that repository.

use clap::Parser;
use clap_derive::*;
use openmls::prelude::*;

use openmls::prelude::config::CryptoConfig;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsCryptoProvider;
use serde::{self, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt::Display, fs::File, io::Write, sync::Mutex};
use tonic::{transport::Server, Request, Response, Status};

use openmls_rust_crypto::OpenMlsRustCrypto;

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::*;

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "OpenMLS";

/// This struct contains the state for a single MLS client. The interop client
/// doesn't consider scenarios where a credential is re-used across groups, so
/// this simple structure is sufficient.
pub struct InteropGroup {
    group: MlsGroup,
    wire_format_policy: WireFormatPolicy,
    // credential: Credential,
    signature_keys: SignatureKeyPair,
}

/// This is the main state struct of the interop client. It keeps track of the
/// individual MLS clients, as well as pending key packages that it was told to
/// create. It also contains a transaction id map, that maps the `u32`
/// transaction ids to key package hashes.
pub struct MlsClientImpl {
    groups: Mutex<Vec<InteropGroup>>,
    pending_key_packages: Mutex<HashMap<Vec<u8>, (KeyPackage, Credential, SignatureKeyPair)>>,
    /// Note that the client currently doesn't really use transaction ids and
    /// instead relies on the KeyPackage hash in the Welcome message to identify
    /// what key package to use when joining a group.
    transaction_id_map: Mutex<HashMap<u32, Vec<u8>>>,
    crypto_provider: OpenMlsRustCrypto,
}

impl MlsClientImpl {
    /// A simple constructor for `MlsClientImpl`.
    fn new() -> Self {
        MlsClientImpl {
            groups: Mutex::new(Vec::new()),
            pending_key_packages: Mutex::new(HashMap::new()),
            transaction_id_map: Mutex::new(HashMap::new()),
            crypto_provider: OpenMlsRustCrypto::default(),
        }
    }
}

fn into_status<E: Display>(e: E) -> Status {
    let message = "mls group error ".to_string() + &e.to_string();
    tonic::Status::new(tonic::Code::Aborted, message)
}

fn to_ciphersuite(cs: u32) -> Result<&'static Ciphersuite, Status> {
    let cs_name = match Ciphersuite::try_from(cs as u16) {
        Ok(cs_name) => cs_name,
        Err(_) => {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
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
        None => Err(tonic::Status::new(
            tonic::Code::InvalidArgument,
            "ciphersuite not supported by this configuration of OpenMLS",
        )),
    }
}

fn _into_bytes(obj: impl Serialize) -> Vec<u8> {
    serde_json::to_string_pretty(&obj)
        .expect("Error serializing test vectors")
        .as_bytes()
        .to_vec()
}

pub fn write(file_name: &str, payload: &[u8]) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
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

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        log::trace!("Got Name request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        log::trace!("Got SupportedCiphersuites request");

        // TODO: read from backend
        let ciphersuites = &[
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        ];
        let response = SupportedCiphersuitesResponse {
            ciphersuites: ciphersuites.iter().map(|cs| *cs as u32).collect(),
        };

        Ok(Response::new(response))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let create_group_request = request.get_ref();

        let ciphersuite = Ciphersuite::try_from(create_group_request.cipher_suite as u16).unwrap();
        let credential = Credential::new("OpenMLS".into(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys
            .store(self.crypto_provider.key_store())
            .unwrap();

        let wire_format_policy = wire_format_policy(create_group_request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(wire_format_policy)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.crypto_provider,
            &signature_keys,
            &mls_group_config,
            GroupId::from_slice(&create_group_request.group_id),
            CredentialWithKey {
                credential: credential.clone(),
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(into_status)?;

        let interop_group = InteropGroup {
            // credential: credential.clone(),
            wire_format_policy,
            group,
            signature_keys,
        };

        let mut groups = self.groups.lock().unwrap();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        Ok(Response::new(CreateGroupResponse { state_id }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let create_kp_request = request.get_ref();

        let ciphersuite = *to_ciphersuite(create_kp_request.cipher_suite)?;
        let credential = Credential::new("OpenMLS".into(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys
            .store(self.crypto_provider.key_store())
            .unwrap();

        let key_package = KeyPackage::builder()
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                &self.crypto_provider,
                &signature_keys,
                CredentialWithKey {
                    credential: credential.clone(),
                    signature_key: signature_keys.public().into(),
                },
            )
            .unwrap();

        let mut transaction_id_map = self.transaction_id_map.lock().unwrap();
        let transaction_id = transaction_id_map.len() as u32;
        transaction_id_map.insert(
            transaction_id,
            key_package
                .hash_ref(self.crypto_provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
        );

        self.pending_key_packages.lock().unwrap().insert(
            key_package
                .hash_ref(self.crypto_provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            (key_package.clone(), credential, signature_keys),
        );

        Ok(Response::new(CreateKeyPackageResponse {
            transaction_id,
            key_package: key_package
                .tls_serialize_detached()
                .expect("error serializing key package"),
        }))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let join_group_request = request.get_ref();

        let wire_format_policy = wire_format_policy(join_group_request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(wire_format_policy)
            .use_ratchet_tree_extension(true)
            .build();

        let welcome = Welcome::tls_deserialize(&mut join_group_request.welcome.as_slice()).unwrap();
        let mut pending_key_packages = self.pending_key_packages.lock().unwrap();
        let (_kpb, _credential, signature_keys) = welcome
            .secrets()
            .iter()
            .find_map(|egs| pending_key_packages.remove(egs.new_member().as_slice()))
            .ok_or_else(|| {
                tonic::Status::new(
                    tonic::Code::NotFound,
                    "No key package could be found for the given Welcome message.",
                )
            })?;
        let group =
            MlsGroup::new_from_welcome(&self.crypto_provider, &mls_group_config, welcome, None)
                .map_err(into_status)?;

        let interop_group = InteropGroup {
            // credential,
            wire_format_policy,
            group,
            signature_keys,
        };

        let mut groups = self.groups.lock().unwrap();
        let state_id = groups.len() as u32;
        groups.push(interop_group);

        Ok(Response::new(JoinGroupResponse { state_id }))
    }

    async fn external_join(
        &self,
        _request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "external join is not yet supported by OpenMLS",
        ))
    }

    async fn public_group_state(
        &self,
        _request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "exporting public group state is not yet supported by OpenMLS",
        ))
    }

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let state_auth_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(state_auth_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let state_auth_secret = interop_group.group.epoch_authenticator();

        Ok(Response::new(StateAuthResponse {
            state_auth_secret: state_auth_secret.as_slice().to_vec(),
        }))
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        let export_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(export_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        let exported_secret = interop_group
            .group
            .export_secret(
                &self.crypto_provider,
                &export_request.label,
                &export_request.context,
                export_request.key_length as usize,
            )
            .map_err(into_status)?;

        Ok(Response::new(ExportResponse { exported_secret }))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let protect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(protect_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let ciphertext = interop_group
            .group
            .create_message(
                &self.crypto_provider,
                &interop_group.signature_keys,
                &protect_request.application_data,
            )
            .map_err(into_status)?
            .tls_serialize_detached()
            .map_err(|_| Status::aborted("failed to serialize ciphertext"))?;
        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let unprotect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(unprotect_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let message = MlsMessageIn::tls_deserialize(&mut unprotect_request.ciphertext.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let processed_message = interop_group
            .group
            .process_message(&self.crypto_provider, message)
            .map_err(into_status)?;
        let application_data = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                application_message.into_bytes()
            }
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
        };

        Ok(Response::new(UnprotectResponse { application_data }))
    }

    async fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let add_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(add_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let key_package =
            KeyPackage::tls_deserialize(&mut add_proposal_request.key_package.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize key package"))?;
        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        let proposal = interop_group
            .group
            .propose_add_member(
                &self.crypto_provider,
                &interop_group.signature_keys,
                &key_package,
            )
            .map_err(into_status)?
            .to_bytes()
            .unwrap();

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let update_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(update_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        let proposal = interop_group
            .group
            .propose_self_update(&self.crypto_provider, &interop_group.signature_keys, None)
            .map_err(into_status)?
            .to_bytes()
            .unwrap();

        // XXX[FK]: Make sure the new keys are accessible?

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let remove_proposal_request = request.get_ref();
        let removed_credential = Credential::new(
            remove_proposal_request.removed_id.clone(),
            CredentialType::Basic,
        )
        .unwrap();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(remove_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);

        let proposal = interop_group
            .group
            .propose_remove_member_by_credential(
                &self.crypto_provider,
                &interop_group.signature_keys,
                &removed_credential,
            )
            .map_err(into_status)?
            .to_bytes()
            .unwrap();

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default()))
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(commit_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        // Proposals by reference. These proposals are standalone proposals. They should
        // be appended to the proposal store.

        for proposal in &commit_request.by_reference {
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
            let processed_message = interop_group
                .group
                .process_message(&self.crypto_provider, message)
                .map_err(into_status)?;
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    interop_group.group.store_pending_proposal(*proposal);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
            }
        }

        // Proposals by value. These proposals are inline proposals. They should be
        // converted into group operations.

        // TODO #692: The interop client cannot process these proposals yet.

        let (commit, welcome_option, _group_info) = interop_group
            .group
            .self_update(&self.crypto_provider, &interop_group.signature_keys)
            .map_err(into_status)?;

        let commit = commit.to_bytes().unwrap();

        let welcome = if let Some(welcome) = welcome_option {
            welcome
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize welcome"))?
        } else {
            vec![]
        };
        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        Ok(Response::new(CommitResponse {
            commit,
            welcome,
            epoch_authenticator,
        }))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let handle_commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(handle_commit_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;

        for proposal in &handle_commit_request.proposal {
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
            let processed_message = interop_group
                .group
                .process_message(&self.crypto_provider, message)
                .map_err(into_status)?;
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    interop_group.group.store_pending_proposal(*proposal);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
            }
        }

        let message = MlsMessageIn::tls_deserialize(&mut handle_commit_request.commit.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let processed_message = interop_group
            .group
            .process_message(&self.crypto_provider, message)
            .map_err(into_status)?;
        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(_) => {
                interop_group
                    .group
                    .merge_pending_commit(&self.crypto_provider)
                    .map_err(into_status)?;
            }
        }

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        Ok(Response::new(HandleCommitResponse {
            state_id: handle_commit_request.state_id,
            epoch_authenticator,
        }))
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let _obj = request.get_ref();
        Err(tonic::Status::new(
            tonic::Code::Unimplemented,
            "handling pending commits is not yet supported by OpenMLS",
        ))
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = "[::1]")]
    host: String,

    #[clap(short, long, default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    pretty_env_logger::init();

    let addr = format!("{}:{}", opts.host, opts.port).parse().unwrap();
    let mls_client_impl = MlsClientImpl::new();

    println!("Listening on {}", addr);

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve(addr)
        .await?;

    Ok(())
}
