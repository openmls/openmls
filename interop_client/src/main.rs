//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client in that repository.

use std::{collections::HashMap, convert::TryFrom, fmt::Display, fs::File, io::Write, sync::Mutex};

use clap::Parser;
use clap_derive::*;
use mls_client::{
    mls_client_server::{MlsClient, MlsClientServer},
    *,
};
use mls_interop_proto::mls_client;
use openmls::{
    ciphersuite::HpkePrivateKey,
    credentials::{Credential, CredentialType, CredentialWithKey},
    extensions::{
        Extension, Extensions, ExternalPubExtension, ExternalSendersExtension,
        RatchetTreeExtension, RequiredCapabilitiesExtension,
    },
    framing::{
        MlsMessageIn, MlsMessageInBody, MlsMessageOut, ProcessedMessageContent, TlsFromBytes,
    },
    group::{
        GroupEpoch, GroupId, MlsGroup, MlsGroupConfig, WireFormatPolicy,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    messages::group_info::GroupInfoTBS,
    prelude::{
        config::CryptoConfig,
        group_info::{GroupInfo, VerifiableGroupInfo},
        ApplicationIdExtension, Capabilities, ExtensionType,
        ExtensionType::ApplicationId,
        SenderRatchetConfiguration, UnknownExtension,
    },
    schedule::{psk::ResumptionPskUsage, ExternalPsk, PreSharedKeyId, Psk},
    test_utils::{generate_group_candidate, hex_to_bytes},
    treesync::{
        test_utils::{read_keys_from_key_store, write_keys_from_key_store},
        RatchetTree, TreeSync,
    },
    versions::ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    key_store::OpenMlsKeyStore,
    random::OpenMlsRand,
    types::{Ciphersuite, HpkeKeyPair},
    OpenMlsCryptoProvider,
};
use serde::{self, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};
use tonic::{transport::Server, Code, Request, Response, Status};
use tracing::{debug, error, info, instrument, trace, Span};
use tracing_subscriber::EnvFilter;

const IMPLEMENTATION_NAME: &str = "OpenMLS";

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
    KeyPackage,
    HpkePrivateKey,
    HpkeKeyPair,
    Credential,
    SignatureKeyPair,
    OpenMlsRustCrypto,
);

/// This is the main state struct of the interop client. It keeps track of the
/// individual MLS clients, as well as pending key packages that it was told to
/// create. It also contains a transaction id map, that maps the `u32`
/// transaction ids to key package hashes.
pub struct MlsClientImpl {
    groups: Mutex<Vec<InteropGroup>>,
    pending_state: Mutex<HashMap<Vec<u8>, PendingState>>,
    transaction_id_map: Mutex<HashMap<u32, Vec<u8>>>, // Indirection, linking to pending key packages
}

impl MlsClientImpl {
    /// A simple constructor for `MlsClientImpl`.
    fn new() -> Self {
        MlsClientImpl {
            groups: Mutex::new(Vec::new()),
            pending_state: Mutex::new(HashMap::new()),
            transaction_id_map: Mutex::new(HashMap::new()),
        }
    }
}

fn into_status<E: Display>(e: E) -> Status {
    let message = "mls group error ".to_string() + &e.to_string();
    error!("{message}");
    Status::new(Code::Aborted, message)
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

fn ratchet_tree_from_config(bytes: Vec<u8>) -> Option<RatchetTree> {
    debug!("Deserializing `RatchetTree`.");
    if !bytes.is_empty() {
        let ratchet_tree = RatchetTree::tls_deserialize(&mut bytes.as_slice()).unwrap();
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

#[tonic::async_trait]
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
        request: Request<SupportedCiphersuitesRequest>,
    ) -> Result<Response<SupportedCiphersuitesResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        // TODO: read from backend
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

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all, fields(actor))]
    async fn create_group(
        &self,
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let backend = OpenMlsRustCrypto::default();

        let ciphersuite = Ciphersuite::try_from(request.cipher_suite as u16).unwrap();
        let credential = Credential::new(request.identity.clone(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys.store(backend.key_store()).unwrap();

        let wire_format_policy = wire_format_policy(request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();
        let group = MlsGroup::new_with_group_id(
            &backend,
            &signature_keys,
            &mls_group_config,
            GroupId::from_slice(&request.group_id),
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(into_status)?;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));
        trace!(epoch=?group.epoch(), "Current group state.");

        let interop_group = InteropGroup {
            group,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider: backend,
        };

        let mut groups = self.groups.lock().unwrap();
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

        let credential = Credential::new(identity, CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(Capabilities::default())
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                &crypto_provider,
                &signature_keys,
                CredentialWithKey {
                    credential: credential.clone(),
                    signature_key: signature_keys.public().into(),
                },
            )
            .unwrap();
        let private_key = crypto_provider
            .key_store()
            .read::<HpkePrivateKey>(key_package.hpke_init_key().as_slice())
            .unwrap();

        let encryption_key_pair =
            read_keys_from_key_store(&crypto_provider, key_package.leaf_node().encryption_key());

        let transaction_id: [u8; 4] = crypto_provider.rand().random_array().unwrap();
        let transaction_id = u32::from_be_bytes(transaction_id);

        let key_package_msg: MlsMessageOut = key_package.clone().into();
        let response = CreateKeyPackageResponse {
            transaction_id,
            key_package: key_package_msg
                .tls_serialize_detached()
                .expect("error serializing key package"),
            encryption_priv: encryption_key_pair
                .private
                .tls_serialize_detached()
                .unwrap(),
            init_priv: private_key.tls_serialize_detached().unwrap(),
            signature_priv: signature_keys.private().to_vec(),
        };

        self.transaction_id_map
            .lock()
            .unwrap()
            .insert(transaction_id, request.identity.clone());
        self.pending_state.lock().unwrap().insert(
            request.identity.clone(),
            (
                key_package,
                private_key,
                encryption_key_pair,
                credential,
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
        let mls_group_config = MlsGroupConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .sender_ratchet_configuration(SenderRatchetConfiguration::default())
            .use_ratchet_tree_extension(true)
            .wire_format_policy(wire_format_policy)
            .build();

        let mut pending_key_packages = self.pending_state.lock().unwrap();
        let (
            my_key_package,
            private_key,
            encryption_keypair,
            _my_credential,
            my_signature_keys,
            crypto_provider,
        ) = pending_key_packages
            .remove(&request.identity)
            .ok_or(Status::aborted(format!(
                "failed to find key package for identity {:x?}",
                request.identity
            )))?;

        // Store keys so OpenMLS can find them.
        crypto_provider
            .key_store()
            .store(my_key_package.hpke_init_key().as_slice(), &private_key)
            .map_err(|_| Status::aborted("failed to interact with the key store"))?;

        // Store the key package in the key store with the hash reference as id
        // for retrieval when parsing welcome messages.
        crypto_provider
            .key_store()
            .store(
                my_key_package
                    .hash_ref(crypto_provider.crypto())
                    .map_err(into_status)?
                    .as_slice(),
                &my_key_package,
            )
            .map_err(into_status)?;

        // Store the encryption key pair in the key store.
        write_keys_from_key_store(&crypto_provider, encryption_keypair);

        // Store the private part of the init_key into the key store.
        // The key is the public key.
        crypto_provider
            .key_store()
            .store::<HpkePrivateKey>(my_key_package.hpke_init_key().as_slice(), &private_key)
            .map_err(into_status)?;

        let welcome_msg = MlsMessageIn::tls_deserialize(&mut request.welcome.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize MlsMessage with a Welcome"))?;

        let welcome = welcome_msg.into_welcome().ok_or(Status::invalid_argument(
            "unable to get Welcome from MlsMessage",
        ))?;

        let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

        let group =
            MlsGroup::new_from_welcome(&crypto_provider, &mls_group_config, welcome, ratchet_tree)
                .map_err(into_status)?;

        let interop_group = InteropGroup {
            wire_format_policy,
            group,
            signature_keys: my_signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        let mut groups = self.groups.lock().unwrap();
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
                    MlsMessageInBody::GroupInfo(verifiable_group_info) => verifiable_group_info,
                    other => panic!("Expected `MlsMessageInBody::GroupInfo`, got {other:?}."),
                }
            };
            debug!("Got `VerifiableGroupInfo`.");
            trace!(?verifiable_group_info);

            let ratchet_tree = ratchet_tree_from_config(request.ratchet_tree.clone());

            let backend = OpenMlsRustCrypto::default();

            let credential_with_key_and_signer = {
                let identity = request.identity.to_vec();
                let candidate = generate_group_candidate(
                    &identity,
                    verifiable_group_info.ciphersuite(),
                    Some(&backend),
                );

                candidate.credential_with_key_and_signer
            };

            let mls_group_config = {
                let wire_format_policy = wire_format_policy(request.encrypt_handshake);

                MlsGroupConfig::builder()
                    .max_past_epochs(32)
                    .number_of_resumption_psks(32)
                    .sender_ratchet_configuration(SenderRatchetConfiguration::default())
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(wire_format_policy)
                    .build()
            };

            let (mut group, commit, _group_info) = MlsGroup::join_by_external_commit(
                &backend,
                &credential_with_key_and_signer.signer,
                ratchet_tree,
                verifiable_group_info,
                &mls_group_config,
                b"",
                credential_with_key_and_signer.credential_with_key,
            )
            .unwrap();

            trace!(?commit, "Commit created.");
            debug!(commit=?group.pending_commit(), "Merging pending commit.");
            group.merge_pending_commit(&backend).unwrap();

            (
                InteropGroup {
                    wire_format_policy: mls_group_config.wire_format_policy(),
                    group,
                    signature_keys: credential_with_key_and_signer.signer,
                    messages_out: Vec::new(),
                    crypto_provider: backend,
                },
                commit,
            )
        };

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();

        let mut groups = self.groups.lock().unwrap();
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

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

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

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let exported_secret = interop_group
            .group
            .export_secret(
                &interop_group.crypto_provider,
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!(actor=String::from_utf8_lossy(interop_group.group.own_identity().unwrap()).to_string(), epoch=?interop_group.group.epoch(), "Protecting.");

        // TODO: Move into `create_message`?
        //       Blocked-by: What is this useful for?
        interop_group.group.set_aad(&request.authenticated_data);

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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!(actor=String::from_utf8_lossy(interop_group.group.own_identity().unwrap()).to_string(), epoch=?interop_group.group.epoch(), "Unprotecting.");

        debug!("Deserializing `MlsMessageIn`.");
        let message = MlsMessageIn::tls_deserialize(&mut request.ciphertext.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        debug!("Deserialized `MlsMessageIn`.");
        trace!(?message);

        debug!("Processing message.");
        let processed_message = interop_group
            .group
            .process_message(&interop_group.crypto_provider, message)
            .map_err(into_status)?;
        debug!("Processed.");
        trace!(?processed_message);

        let authenticated_data = processed_message.authenticated_data().to_vec();
        let plaintext = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                application_message.into_bytes()
            }
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
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
                .write_to_key_store(crypto_provider, ciphersuite, secret)
                .map_err(|_| Status::new(Code::Internal, "unable to store PSK"))?;
            Ok(())
        }

        // This might be for a transaction ID or a state ID, so either a group, or not.
        // Transaction IDs are random. We assume that if it exists, it is what we want.
        let transaction_id_map = self.transaction_id_map.lock().unwrap();
        let pending_state_id = transaction_id_map.get(&request.state_or_transaction_id);
        if let Some(pending_state_id) = pending_state_id {
            let mut pending_state = self.pending_state.lock().unwrap();
            let pending_state = pending_state
                .get_mut(pending_state_id)
                .ok_or(Status::internal("Unable to retrieve pending state"))?;

            store(
                pending_state.0.ciphersuite(),
                &pending_state.5,
                external_psk,
                &request.psk_secret,
            )?;
        } else {
            // So we have a group
            let mut groups = self.groups.lock().unwrap();
            let interop_group = groups
                .get_mut(request.state_or_transaction_id as usize)
                .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
            trace!("   in epoch {:?}", interop_group.group.epoch());
            trace!(
                "   actor {:x?}",
                String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
            );

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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

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
        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
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

        // trace!("   proposal: {proposal:#x?}");
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let mls_group_config = MlsGroupConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        let (proposal, _) = interop_group
            .group
            .propose_self_update(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                None,
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

        let removed_credential =
            Credential::new(request.removed_id.clone(), CredentialType::Basic).unwrap();
        trace!("   for credential: {removed_credential:x?}");

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let mls_group_config = MlsGroupConfig::builder()
            .max_past_epochs(32)
            .number_of_resumption_psks(32)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        trace!("   prepared remove");

        let (proposal, _) = interop_group
            .group
            .propose_remove_member_by_credential(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                &removed_credential,
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

        let response = Status::unimplemented("Re-init is not implemented");

        info!(?response, "Response");
        Err(response)
    }

    #[instrument(skip_all, fields(actor))]
    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));
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
                .process_message(&interop_group.crypto_provider, message)
                .map_err(into_status)?;
            trace!("... done");

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    group.store_pending_proposal(*proposal);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
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
                        MlsMessageIn::try_from_bytes(&mut proposal.key_package.clone())
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
                    let removed_credential =
                        Credential::new(proposal.removed_id.clone(), CredentialType::Basic)
                            .unwrap();

                    group
                        .propose_remove_member_by_credential_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            &removed_credential,
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
                        .propose_external_psk_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            psk_id,
                        )
                        .map_err(|_| Status::internal("Unable to generate proposal by value"))?
                }
                "resumptionPSK" => {
                    let psk_id = PreSharedKeyId::resumption(
                        ResumptionPskUsage::Application,
                        group.group_id().clone(),
                        GroupEpoch::from(proposal.epoch_id),
                        "B".repeat(group.ciphersuite().hash_length()).into_bytes(),
                    );

                    // TODO: epoch_id vs epoch?
                    let (msg_out, proposal_ref) = group
                        .propose_external_psk_by_value(
                            &interop_group.crypto_provider,
                            &interop_group.signature_keys,
                            psk_id,
                        )
                        .unwrap();
                    debug!("Resumption PSK proposal created.");
                    trace!(proposal = ?msg_out);
                    trace!(proposal_ref = ?proposal_ref);

                    (msg_out, proposal_ref)
                }
                "groupContextExtensions" => {
                    return Err(Status::internal(
                        "Unsupported proposal type (group context extension)",
                    ))
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

        // REMOVE this
        // debug!(commit=?group.pending_commit(), "Merging pending commit.");
        // group
        //     .merge_pending_commit(&interop_group.crypto_provider)
        //     .map_err(into_status)?;
        // trace!(epoch=?group.epoch(), "New group state.");

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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));
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
                .process_message(&interop_group.crypto_provider, message)
                .map_err(into_status)?;
            trace!("       done");
            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    group.store_pending_proposal(*proposal);
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
                ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
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
            .process_message(&interop_group.crypto_provider, message)
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));

        let group_info = group
            .export_group_info(
                &interop_group.crypto_provider,
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        trace!("   in epoch {:?}", interop_group.group.epoch());
        trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

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
            .propose_external_psk(
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

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        Span::current().record("actor", bytes_to_string(group.own_identity().unwrap()));

        let psk_id = PreSharedKeyId::resumption(
            ResumptionPskUsage::Application,
            group.group_id().clone(),
            GroupEpoch::from(request.epoch_id),
            "A".repeat(group.ciphersuite().hash_length()).into_bytes(),
        );

        let (msg_out, proposal_ref) = interop_group
            .group
            .propose_external_psk(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                psk_id,
            )
            .unwrap();
        debug!("Resumption PSK proposal created.");
        trace!(proposal = ?msg_out);

        let response = ProposalResponse {
            proposal: msg_out.tls_serialize_detached().unwrap(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    #[instrument(skip_all)]
    async fn group_context_extensions_proposal(
        &self,
        request: Request<GroupContextExtensionsProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        let request = request.get_ref();
        info!(?request, "Request");

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(request.state_id as usize)
            .ok_or_else(|| Status::new(Code::InvalidArgument, "unknown state_id"))?;
        let group = &mut interop_group.group;

        // GroupContextExtensionsProposalRequest { extensions: [Extension { extension_type: 3, extension_data: [0, 0, 0] }, Extension { extension_type: 5, extension_data: [0] }] }
        let extensions = {
            let mut extensions = Vec::new();

            for ext in request.extensions.iter() {
                let kind =
                    ExtensionType::try_from(u16::try_from(ext.extension_type).unwrap()).unwrap();

                let extension = match kind {
                    ExtensionType::ApplicationId => {
                        ApplicationIdExtension::try_from_bytes(&ext.extension_data)
                            .unwrap()
                            .into()
                    }
                    ExtensionType::RatchetTree => {
                        RatchetTreeExtension::try_from_bytes(&ext.extension_data)
                            .unwrap()
                            .into()
                    }
                    ExtensionType::RequiredCapabilities => {
                        RequiredCapabilitiesExtension::try_from_bytes(&ext.extension_data)
                            .unwrap()
                            .into()
                    }
                    ExtensionType::ExternalPub => {
                        ExternalPubExtension::try_from_bytes(&ext.extension_data)
                            .unwrap()
                            .into()
                    }
                    ExtensionType::ExternalSenders => {
                        ExternalSendersExtension::try_from_bytes(&ext.extension_data)
                            .unwrap()
                            .into()
                    }
                    ExtensionType::Unknown(unknown) => {
                        Extension::Unknown(unknown, UnknownExtension(vec![0, 1, 2, 3, 255]))
                    }
                };

                extensions.push(extension);
            }

            Extensions::try_from(extensions).unwrap()
        };

        let (msg_out, proposal_ref) = group
            .propose_group_context_extensions(
                &interop_group.crypto_provider,
                extensions,
                &interop_group.signature_keys,
            )
            .unwrap();

        let response = ProposalResponse {
            proposal: msg_out.tls_serialize_detached().unwrap(),
        };

        info!(?response, "Response");
        Ok(Response::new(response))
    }

    async fn re_init_commit(
        &self,
        _: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        todo!()
    }

    async fn handle_pending_re_init_commit(
        &self,
        _: Request<HandlePendingCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        todo!()
    }

    async fn handle_re_init_commit(
        &self,
        _: Request<HandleCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        todo!()
    }

    async fn re_init_welcome(
        &self,
        _: Request<ReInitWelcomeRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        todo!()
    }

    async fn handle_re_init_welcome(
        &self,
        _: Request<HandleReInitWelcomeRequest>,
    ) -> Result<Response<JoinGroupResponse>, Status> {
        todo!()
    }

    async fn create_branch(
        &self,
        _: Request<CreateBranchRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        todo!()
    }

    async fn handle_branch(
        &self,
        _: Request<HandleBranchRequest>,
    ) -> Result<Response<HandleBranchResponse>, Status> {
        todo!()
    }

    async fn new_member_add_proposal(
        &self,
        _: Request<NewMemberAddProposalRequest>,
    ) -> Result<Response<NewMemberAddProposalResponse>, Status> {
        todo!()
    }

    async fn create_external_signer(
        &self,
        _: Request<CreateExternalSignerRequest>,
    ) -> Result<Response<CreateExternalSignerResponse>, Status> {
        todo!()
    }

    async fn add_external_signer(
        &self,
        _: Request<AddExternalSignerRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        todo!()
    }

    async fn external_signer_proposal(
        &self,
        _: Request<ExternalSignerProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        todo!()
    }

    async fn re_init_commit(
        &self,
        _: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        todo!()
    }

    async fn handle_pending_re_init_commit(
        &self,
        _: Request<HandlePendingCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        todo!()
    }

    async fn handle_re_init_commit(
        &self,
        _: Request<HandleCommitRequest>,
    ) -> Result<Response<HandleReInitCommitResponse>, Status> {
        todo!()
    }

    async fn re_init_welcome(
        &self,
        _: Request<ReInitWelcomeRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        todo!()
    }

    async fn handle_re_init_welcome(
        &self,
        _: Request<HandleReInitWelcomeRequest>,
    ) -> Result<Response<JoinGroupResponse>, Status> {
        todo!()
    }

    async fn create_branch(
        &self,
        _: Request<CreateBranchRequest>,
    ) -> Result<Response<CreateSubgroupResponse>, Status> {
        todo!()
    }

    async fn handle_branch(
        &self,
        _: Request<HandleBranchRequest>,
    ) -> Result<Response<HandleBranchResponse>, Status> {
        todo!()
    }

    async fn new_member_add_proposal(
        &self,
        _: Request<NewMemberAddProposalRequest>,
    ) -> Result<Response<NewMemberAddProposalResponse>, Status> {
        todo!()
    }

    async fn create_external_signer(
        &self,
        _: Request<CreateExternalSignerRequest>,
    ) -> Result<Response<CreateExternalSignerResponse>, Status> {
        todo!()
    }

    async fn add_external_signer(
        &self,
        _: Request<AddExternalSignerRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        todo!()
    }

    async fn external_signer_proposal(
        &self,
        _: Request<ExternalSignerProposalRequest>,
    ) -> Result<Response<ProposalResponse>, Status> {
        todo!()
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(long, default_value = "[::1]")]
    host: String,

    #[clap(short, long, default_value = "50051")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /*
        let vgi = MlsMessageIn::tls_deserialize(&mut hex_to_bytes("00010004000100012466316533393136652d633333642d346236352d613465312d346366303061333231323030000000000000000020443e6bed3585fb51388d4bdb3c6d1e91fb97e6dcfc744d141c99ac02266cc7fe000040e100042120ac4187979f46e57908d5f26865158a162f22929c13ab5611d002d016ed506d31000240b940b7010120e945f08d3e66b6678fdad05a12521b5ac4bd9eb0b13534595d1a909918d6052420f2835df5e1194963a6c32c22ef3512745af841cb268a7a3e1f74632ffa070efd000105616c6963650200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040467869ce4e8cd0c3a24445f99efdcea398c1938429c7244eeb0ed2deee9b25a5b81bce7b4f70617b75edfad8f244776e177fde787a86ce916df78ecef0cf620420a0682e5620669dc593e05c0ecc0c9eb9caa866dd0a0329925b79dba2c8958d8600000000404038ac710899b158f0db0d0aa4c740f083541142f27e1c6bfbd8544d7c408d20e551a29de3a8f2ea533de8c549c0591316e5a3cade011fbc4f316a687e53a9a506").as_slice()).unwrap().into_verifiable_group_info().unwrap();

        let backend = OpenMlsRustCrypto::default();

        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let group_info: GroupInfo = {
            let treesync = TreeSync::from_ratchet_tree(&backend, ciphersuite, vgi.extensions().ratchet_tree().unwrap().ratchet_tree().clone())?;

            let signer_signature_key = treesync
                .leaf(vgi.signer())
                .unwrap()
                .signature_key()
                .clone()
                .into_signature_public_key_enriched(ciphersuite.signature_algorithm());

            vgi
                .verify(backend.crypto(), &signer_signature_key)
                .map_err(|_| CreationFromExternalError::InvalidGroupInfoSignature)?
        };

        dbg!(group_info);

        std::process::exit(1);
    */

    /*
    dbg!(MlsMessageIn::try_from_bytes(hex_to_bytes("000100012465626635396537302d366430652d343837302d626363372d663237343162336430353036000000000000000101000000010002000220562032492f0df18f4cbbb090a472ea5bbce359247ff7d7754b10148dea25594520ed63ad0b379947829e9af64f194e045f6264a220dd9a798e8d5de290c1ba94c2000103626f62020001060001000200030200010c0001000200030004000500070200010320e2636a47ea37b18301cbf2b82de54b1baed31f4649dfe10608c1a0e7213017070040401c3ae9d2928b63ba413a1f72891aa76ca52f2c189b899d28d694100292a8e2fac1ee70c2ebc7e16f6dc13574f21827e11bb96af2a446d2450f13c368a32732064040fd25bbfb4bdc06125e26143edc7c2cdaeec8e05c8549a5571261fe722bd206a91db65fd6fa24c8249df009e99a13e234b0223c41967309d18202801d70c5d30620ebdd031f30ebdae3fd6ae0abee279875e8b0f831bc55bb9226b72d10a90ab089")).unwrap());
    std::process::exit(1);
    */

    /*
    // OpenMLS
    dbg!(GroupContext::tls_deserialize(&mut hex_to_bytes("000100012439343965383662662D346563392D343937392D623538302D63346135336539643831396200000000000000012073CF2FDCD795022F2628DBABF9A6B3F79DE69CC31662B2C61AC3210FE989700A0006000303000000").as_slice()).unwrap());
    // mlspp
    dbg!(GroupContext::tls_deserialize(&mut hex_to_bytes("000100012439343965383662662d346563392d343937392d623538302d63346135336539643831396200000000000000012073cf2fdcd795022f2628dbabf9a6b3f79de69cc31662b2c61ac3210fe989700a203ea9fa848b589a83478b9a820f313d9726bb310f85fef43df1afeb2cb68fffd006000303000000").as_slice()).unwrap());

    std::process::exit(1);
    */

    /*
    // OpenMLS
    dbg!(GroupInfoTBS::tls_deserialize(&mut hex_to_bytes("000100012435363939346561392D363937362D346466642D383366322D3136303966316136373630310000000000000000202B8C39B009BCC32B0F5B84445AD179EDD1D402D4697E8E8694B87CCCA21B7952000040E1000240B940B701012013F3B01F2C26F2E9389067BC8E63CD816B2F6925B785D9C5AEA770671BF1670520BCB2BC7F74E716504799D5C8463AA0D94011F31684C3C75FD77D061AF6158057000105616C6963650200010C00010002000300040005000600000400010002010000000000000000FFFFFFFFFFFFFFFF0040404E20AE6DC4A1015C602618A3417EB6BF454DF861681DD4CBDC53F91F0A3B1BCEC331C9DC17977ADF3BC51233121B1EA9B37F0A9CDFD2AD8F223429FC89252207000421208FD09B3295BC374156376E9C8DFAF438F3BCC3EB95410B65F5D202F6F1C6BD3020ADD34672394745AC13E83A76DF32E6F1FF98730DD990E4DBB2436EBF3B3FE38800000000").as_slice()).unwrap());
    // mlspp
    dbg!(GroupInfoTBS::tls_deserialize(&mut hex_to_bytes("000100012435363939346561392d363937362d346466642d383366322d3136303966316136373630310000000000000000202b8c39b009bcc32b0f5b84445ad179edd1d402d4697e8e8694b87ccca21b7952000040e1000421208fd09b3295bc374156376e9c8dfaf438f3bcc3eb95410b65f5d202f6f1c6bd30000240b940b701012013f3b01f2c26f2e9389067bc8e63cd816b2f6925b785d9c5aea770671bf1670520bcb2bc7f74e716504799d5c8463aa0d94011f31684c3c75fd77d061af6158057000105616c6963650200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff0040404e20ae6dc4a1015c602618a3417eb6bf454df861681dd4cbdc53f91f0a3b1bcec331c9dc17977adf3bc51233121b1ea9b37f0a9cdfd2ad8f223429fc8925220720add34672394745ac13e83a76df32e6f1ff98730dd990e4dbb2436ebf3b3fe38800000000").as_slice()).unwrap());
    std::process::exit(1);
    */

    /*
    dbg!(vec![Extension::ApplicationId(ApplicationIdExtension::new(
        b"\xff\xff"
    ))]
    .tls_serialize_detached()
    .unwrap());

    dbg!(Vec::<Extension>::tls_deserialize(
        &mut vec![6, 0, 1, 3, 2, 255, 255].as_slice()
    ));

    dbg!(MlsMessageIn::try_from_bytes(&mut hex_to_bytes("00010005000100012028b2cd6417984dc4708c61a1cce7c0f11d181bd36d6f7a610ea21cb96f79ba6020275d9e6337b11a5e21ba755f2353053a500103efa1c5ac7c07d3a78f8817ad2d203de79c7e370156ce25a88d897a8ea7c8f90fea1f71fbeb5f31855312d8750007000120b640fbb0df8e646b29c83c5ed08aea89f72ab108922827ea76cd3b917d6d99420200010c00010002000300040005000600000400010002010000000000000000ffffffffffffffff004040fd81837a40a9ba774bb44db665081f4d0ff2a8f680ce5c902b17acc4ae6d9a14b9d4e9b4f8e7d74af8ff42032ec9caadf267e85931b550eebbe480150d4b9b0a0040401ec696ab731d5a7b1092b0db9912fe35086e188ce2946996bdf3cec463849f1a32f653b6e246b8b85a486ce3f604891501052c3d7bbee2155fff6a367e5a1f03")));
    dbg!(MlsMessageIn::try_from_bytes(&mut hex_to_bytes("0001000500010001206659e0a1f51f237bdcd555b932340fbd024e84b29165658c704f95a6caea824e20b237c3add5f77711a41ff76a2e172d5ea9667e26294c5e14533ede712971705820f693ff236df3ef9447095d44d48e2e3a8c08cb390cb0e66d8f219c7a53f7a5be000103626f620200011000010002eaea00030004000500060a0a023a3a02caca064a4a00010002010000000000000000ffffffffffffffff129a9a0f1b07aa161271d6a045ba83805ba368404033ff71034f36e63667f2378978d293a5433d563cc0e72d65070dda40abf162ebbda24039dc4ebde7d5506dcc82e303fefcf5078fe40a1726b0f7a30acd7ed7080c5a5a094b4ef48b400147429e4040fe5bccc0e621ea9ee2ab400ef6cf556cdb41b610be485df116ab3f93795bcf7e15c9f884690f8fa424c78598e30f6eb084369541e75d538e9d400eef260b0302")));
    std::process::exit(1);
    */

    //dbg!(MlsMessageIn::try_from_bytes(&mut hex_to_bytes("000100012461353133326565662d346634612d343032652d396162652d326136363862336163383730000000000000000101000000010002000220ea423f54b9af8b87e51e3ea15bb4e1531aaeceff2cd3c0b8eb3a2dfd772b2d1f203c32793198525c32a4e52426e10b6e85ecc3f5db1e591165011fb9bad83bc0fe000103626f62020001060001000200030200010002000103207db66ab6f384866b73a71aef68c00e99b460d8027db9f78aae1fd91b85f2b10500404088d004a21d9ab31214e375bc36768285494c71dae2dbbcef28ad5462f7ef95cfd805a5be90fc0918e4d23f792fc90f97d9eb6d8628632740a2e421e1af8dbe09404009baaad49764a2264db12927e85e08e8c431400828b5003b015e606e7d37ef7766dd7cfabe7700efa5d6af1191d37f37764a47b45b3f8b1767a5b20667bc23092098b582d3ed1e3cf771d5c043e24ade319d1956decae37343fc5f150347387524")));
    //std::process::exit(1);

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
