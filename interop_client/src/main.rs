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
    prelude::{config::CryptoConfig, *},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    treesync::test_utils::{read_keys_from_key_store, write_keys_from_key_store},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use serde::{self, Serialize};
use tonic::{transport::Server, Request, Response, Status};

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
    log::error!("{message}");
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
        log::debug!("Got Name request");

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
            ciphersuites: ciphersuites
                .iter()
                .map(|cs| u16::from(*cs) as u32)
                .collect(),
        };

        Ok(Response::new(response))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        log::debug!("Creating a new group.");
        let create_group_request = request.get_ref();
        let crypto_provider = OpenMlsRustCrypto::default();

        let ciphersuite = Ciphersuite::try_from(create_group_request.cipher_suite as u16).unwrap();
        let credential =
            Credential::new(create_group_request.identity.clone(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys.store(crypto_provider.key_store()).unwrap();
        log::trace!("   for {:x?}", create_group_request.identity);

        let wire_format_policy = wire_format_policy(create_group_request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .crypto_config(CryptoConfig::with_default_version(ciphersuite))
            .wire_format_policy(wire_format_policy)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &crypto_provider,
            &signature_keys,
            &mls_group_config,
            GroupId::from_slice(&create_group_request.group_id),
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(into_status)?;

        let interop_group = InteropGroup {
            group,
            wire_format_policy,
            signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
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
        log::debug!("Creating a new key package");
        let create_kp_request = request.get_ref();
        let crypto_provider = OpenMlsRustCrypto::default();

        let ciphersuite = *to_ciphersuite(create_kp_request.cipher_suite)?;
        let credential =
            Credential::new(create_kp_request.identity.clone(), CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        log::trace!(
            "   for {:x?}",
            String::from_utf8_lossy(&create_kp_request.identity)
        );

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
            .insert(transaction_id, create_kp_request.identity.clone());
        self.pending_state.lock().unwrap().insert(
            create_kp_request.identity.clone(),
            (
                key_package,
                private_key,
                encryption_key_pair,
                credential,
                signature_keys,
                crypto_provider,
            ),
        );

        Ok(Response::new(response))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        log::debug!("Joining a group");
        let join_group_request = request.get_ref();
        log::trace!(
            "   {}",
            String::from_utf8_lossy(&join_group_request.identity)
        );

        let wire_format_policy = wire_format_policy(join_group_request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(wire_format_policy)
            .use_ratchet_tree_extension(true)
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
            .remove(&join_group_request.identity)
            .ok_or(Status::aborted(format!(
                "failed to find key package for identity {:x?}",
                join_group_request.identity
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

        let welcome_msg = MlsMessageIn::tls_deserialize(&mut join_group_request.welcome.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize MlsMessage with a Welcome"))?;

        let welcome = welcome_msg.into_welcome().ok_or(Status::invalid_argument(
            "unable to get Welcome from MlsMessage",
        ))?;
        let group = MlsGroup::new_from_welcome(&crypto_provider, &mls_group_config, welcome, None)
            .map_err(into_status)?;

        let interop_group = InteropGroup {
            wire_format_policy,
            group,
            signature_keys: my_signature_keys,
            messages_out: Vec::new(),
            crypto_provider,
        };
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
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

        Ok(Response::new(JoinGroupResponse {
            state_id,
            epoch_authenticator,
        }))
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

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        log::debug!("Generating state authenticator secret");
        let state_auth_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(state_auth_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let state_auth_secret = interop_group.group.epoch_authenticator();

        Ok(Response::new(StateAuthResponse {
            state_auth_secret: state_auth_secret.as_slice().to_vec(),
        }))
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        log::debug!("Exporting a secret");
        let export_request = request.get_ref();

        let groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get(export_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let exported_secret = interop_group
            .group
            .export_secret(
                &interop_group.crypto_provider,
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
        log::debug!("Encrypting message (protect)");
        let protect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(protect_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let ciphertext = interop_group
            .group
            .create_message(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                &protect_request.plaintext,
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
        log::debug!("Decrypting message (unprotect)");
        let unprotect_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(unprotect_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let message = MlsMessageIn::tls_deserialize(&mut unprotect_request.ciphertext.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let processed_message = interop_group
            .group
            .process_message(&interop_group.crypto_provider, message)
            .map_err(into_status)?;
        let authenticated_data = processed_message.authenticated_data().to_vec();
        let plaintext = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                application_message.into_bytes()
            }
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(_) => unreachable!(),
        };

        Ok(Response::new(UnprotectResponse {
            plaintext,
            authenticated_data,
        }))
    }

    async fn store_psk(
        &self,
        request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        log::debug!("Store PSK");
        let store_proposal = request.get_ref();

        let raw_psk_id = store_proposal.psk_id.clone();
        log::trace!("   psk_id {:x?}", raw_psk_id);
        let external_psk = Psk::External(ExternalPsk::new(raw_psk_id));

        fn store(
            ciphersuite: Ciphersuite,
            crypto_provider: &OpenMlsRustCrypto,
            external_psk: Psk,
            secret: &[u8],
        ) -> Result<(), tonic::Status> {
            let psk_id = PreSharedKeyId::new(ciphersuite, crypto_provider.rand(), external_psk)
                .map_err(|_| Status::internal("unable to create PreSharedKeyId from raw psk_id"))?;
            psk_id
                .write_to_key_store(crypto_provider, ciphersuite, secret)
                .map_err(|_| tonic::Status::new(tonic::Code::Internal, "unable to store PSK"))?;
            Ok(())
        }

        // This might be for a transaction ID or a state ID, so either a group, or not.
        // Transaction IDs are random. We assume that if it exists, it is what we want.
        let transaction_id_map = self.transaction_id_map.lock().unwrap();
        let pending_state_id = transaction_id_map.get(&store_proposal.state_or_transaction_id);
        if let Some(pending_state_id) = pending_state_id {
            let mut pending_state = self.pending_state.lock().unwrap();
            let pending_state = pending_state
                .get_mut(pending_state_id)
                .ok_or(Status::internal("Unable to retrieve pending state"))?;

            store(
                pending_state.0.ciphersuite(),
                &pending_state.5,
                external_psk,
                &store_proposal.psk_secret,
            )?;
        } else {
            // So we have a group
            let mut groups = self.groups.lock().unwrap();
            let interop_group = groups
                .get_mut(store_proposal.state_or_transaction_id as usize)
                .ok_or_else(|| {
                    tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id")
                })?;
            log::trace!("   in epoch {:?}", interop_group.group.epoch());
            log::trace!(
                "   actor {:x?}",
                String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
            );

            store(
                interop_group.group.ciphersuite(),
                &interop_group.crypto_provider,
                external_psk,
                &store_proposal.psk_secret,
            )?;
        }

        Ok(Response::new(StorePskResponse::default()))
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        log::debug!("Create add proposal");
        let add_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(add_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let key_package =
            MlsMessageIn::tls_deserialize(&mut add_proposal_request.key_package.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize key package (MlsMessage)"))?
                .into_keypackage()
                .ok_or(Status::aborted("failed to deserialize key package"))?;
        log::trace!(
            "   for {:#x?}",
            key_package
                .hash_ref(interop_group.crypto_provider.crypto())
                .unwrap()
        );
        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
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

        // log::trace!("   proposal: {proposal:#x?}");
        let proposal = proposal.to_bytes().unwrap();

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        log::debug!("Creating update proposal");
        let update_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(update_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let mls_group_config = MlsGroupConfig::builder()
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

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        log::debug!("Generate remove proposal");
        let remove_proposal_request = request.get_ref();
        let removed_credential = Credential::new(
            remove_proposal_request.removed_id.clone(),
            CredentialType::Basic,
        )
        .unwrap();
        log::trace!("   for credential: {removed_credential:x?}");

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(remove_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        log::trace!("   prepared remove");

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
        log::trace!("   generated remove proposal");

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Re-init is not implemented"))
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        log::debug!("Create a commit");
        let commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(commit_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        // Proposals by reference. These proposals are standalone proposals. They should
        // be appended to the proposal store.

        // XXX[FK] This API is pretty bad.

        for proposal in &commit_request.by_reference {
            // log::trace!("   proposals by reference ... we don't care.");
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                log::trace!("   skipping processing of own proposal");
                continue;
            }
            log::trace!("   processing proposal ...");
            let processed_message = interop_group
                .group
                .process_message(&interop_group.crypto_provider, message)
                .map_err(into_status)?;
            log::trace!("       done");
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
            .commit_to_pending_proposals(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
            )
            .map_err(into_status)?;
        // log::trace!("   generated Welcome: {welcome_option:?}");

        let commit = commit.to_bytes().unwrap();

        let welcome = if let Some(welcome) = welcome_option {
            welcome
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize welcome"))?
        } else {
            vec![]
        };

        interop_group
            .group
            .merge_pending_commit(&interop_group.crypto_provider)
            .map_err(into_status)?;

        let ratchet_tree = if commit_request.external_tree {
            interop_group
                .group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize ratchet tree"))?
        } else {
            vec![]
        };

        // log::trace!("   generated Welcome bytes: {welcome:x?}");
        log::trace!("   done committing");

        Ok(Response::new(CommitResponse {
            commit,
            welcome,
            ratchet_tree,
        }))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        log::debug!("Handling incoming commit");
        let handle_commit_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(handle_commit_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        // XXX[FK]: This is a horrible API.

        for proposal in &handle_commit_request.proposal {
            // log::trace!("   proposals by reference ... we don't care.");
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize proposal"))?;
            if interop_group.messages_out.contains(&message) {
                log::trace!("   skipping processing of own proposal");
                continue;
            }
            log::trace!("   processing proposal ...");
            let processed_message = interop_group
                .group
                .process_message(&interop_group.crypto_provider, message)
                .map_err(into_status)?;
            log::trace!("       done");
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
            .map_err(|_| {
            log::error!("Failed to deserialize ciphertext");
            Status::aborted("failed to deserialize ciphertext")
        })?;
        let processed_message = interop_group
            .group
            .process_message(&interop_group.crypto_provider, message)
            .map_err(into_status)?;

        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(_) => unreachable!(),
            ProcessedMessageContent::ProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => unreachable!(),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                log::trace!("   merging pending commit");
                interop_group
                    .group
                    .merge_staged_commit(&interop_group.crypto_provider, *staged_commit)
                    .map_err(into_status)?;
            }
        }

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();
        log::trace!("   new epoch {:?}", interop_group.group.epoch());

        Ok(Response::new(HandleCommitResponse {
            state_id: handle_commit_request.state_id,
            epoch_authenticator,
        }))
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        log::debug!("Handling pending commit");
        let obj = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(obj.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        interop_group
            .group
            .merge_pending_commit(&interop_group.crypto_provider)
            .map_err(|e| {
                log::trace!("   Error merging pending commits {e:?}");
                Status::aborted("failed to apply pending commits")
            })?;
        log::trace!("   merged pending commits.");

        let epoch_authenticator = interop_group
            .group
            .epoch_authenticator()
            .as_slice()
            .to_vec();
        let response = HandleCommitResponse {
            state_id: obj.state_id,
            epoch_authenticator,
        };
        Ok(Response::new(response))
    }

    async fn group_info(
        &self,
        request: tonic::Request<GroupInfoRequest>,
    ) -> Result<tonic::Response<GroupInfoResponse>, tonic::Status> {
        log::debug!("Getting group info");
        let obj = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(obj.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let group_info = interop_group
            .group
            .export_group_info(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                !obj.external_tree,
            )
            .map_err(|_| tonic::Status::internal("Unable to export group info from the group"))?
            .tls_serialize_detached()
            .map_err(|_| tonic::Status::internal("Unable to serialize group info message."))?;

        let ratchet_tree = if obj.external_tree {
            interop_group
                .group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|_| tonic::Status::internal("Unable to serialize ratchet tree."))?
        } else {
            vec![]
        };

        Ok(Response::new(GroupInfoResponse {
            group_info,
            ratchet_tree,
        }))
    }

    async fn external_psk_proposal(
        &self,
        request: tonic::Request<ExternalPskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        log::debug!("Create external PSK proposal");
        let psk_proposal_request = request.get_ref();

        let mut groups = self.groups.lock().unwrap();
        let interop_group = groups
            .get_mut(psk_proposal_request.state_id as usize)
            .ok_or_else(|| tonic::Status::new(tonic::Code::InvalidArgument, "unknown state_id"))?;
        log::trace!("   in epoch {:?}", interop_group.group.epoch());
        log::trace!(
            "   actor {:x?}",
            String::from_utf8_lossy(interop_group.group.own_identity().unwrap())
        );

        let raw_psk_id = psk_proposal_request.psk_id.clone();
        log::trace!("   psk_id {:x?}", raw_psk_id);
        let external_psk = Psk::External(ExternalPsk::new(raw_psk_id));

        let psk_id = PreSharedKeyId::new(
            interop_group.group.ciphersuite(),
            interop_group.crypto_provider.rand(),
            external_psk,
        )
        .map_err(|_| Status::internal("unable to create PreSharedKeyId from raw psk_id"))?;

        let proposal = interop_group
            .group
            .propose_external_psk(
                &interop_group.crypto_provider,
                &interop_group.signature_keys,
                psk_id,
            )
            .map_err(|_| tonic::Status::internal("failed to generate psk proposal"))?;

        // Store the proposal for potential future use.
        interop_group.messages_out.push(proposal.clone().into());

        // log::trace!("   proposal: {proposal:#x?}");
        let proposal = proposal.to_bytes().unwrap();

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn resumption_psk_proposal(
        &self,
        _request: tonic::Request<ResumptionPskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Resumption PSK is not implemented",
        ))
    }

    async fn group_context_extensions_proposal(
        &self,
        _request: tonic::Request<GroupContextExtensionsProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Group context extension is not implemented yet",
        ))
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
