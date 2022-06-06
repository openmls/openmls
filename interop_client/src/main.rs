//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client written by Richard Barnes.

use clap::Parser;
use clap_derive::*;
use openmls::{prelude::*, prelude_test::*};

use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::OpenMlsCryptoProvider;
use serde::{self, Serialize};
use std::{collections::HashMap, convert::TryFrom, fmt::Display, fs::File, io::Write, sync::Mutex};
use tonic::{transport::Server, Request, Response, Status};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
use mls_client::*;

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "OpenMLS";

impl TryFrom<i32> for TestVectorType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TestVectorType::TreeMath),
            1 => Ok(TestVectorType::Encryption),
            2 => Ok(TestVectorType::KeySchedule),
            3 => Ok(TestVectorType::Transcript),
            4 => Ok(TestVectorType::Treekem),
            5 => Ok(TestVectorType::Messages),
            _ => Err(()),
        }
    }
}

/// This struct contains the state for a single MLS client. The interop client
/// doesn't consider scenarios where a credential is re-used across groups, so
/// this simple structure is sufficient.
pub struct InteropGroup {
    group: MlsGroup,
    wire_format_policy: WireFormatPolicy,
    credential_bundle: CredentialBundle,
    own_kpbs: Vec<KeyPackageBundle>,
}

/// This is the main state struct of the interop client. It keeps track of the
/// individual MLS clients, as well as pending key packages that it was told to
/// create. It also contains a transaction id map, that maps the `u32`
/// transaction ids to key package hashes.
pub struct MlsClientImpl {
    groups: Mutex<Vec<InteropGroup>>,
    pending_key_packages: Mutex<HashMap<Vec<u8>, (KeyPackageBundle, CredentialBundle)>>,
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

fn into_bytes(obj: impl Serialize) -> Vec<u8> {
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
        println!("Got Name request");

        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        println!("Got SupportedCiphersuites request");

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

    async fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        let (type_msg, test_vector) = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => {
                let kat_treemath = kat_treemath::generate_test_vector(obj.n_leaves);
                let kat_bytes = into_bytes(kat_treemath);
                ("Tree math", kat_bytes)
            }
            Ok(TestVectorType::Encryption) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_encryption = kat_encryption::generate_test_vector(
                    obj.n_generations,
                    obj.n_leaves,
                    *ciphersuite,
                );
                let kat_bytes = into_bytes(kat_encryption);
                ("Encryption", kat_bytes)
            }
            Ok(TestVectorType::KeySchedule) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_key_schedule =
                    kat_key_schedule::generate_test_vector(obj.n_epochs as u64, *ciphersuite);
                let kat_bytes = into_bytes(kat_key_schedule);
                ("Key Schedule", kat_bytes)
            }
            Ok(TestVectorType::Transcript) => {
                let ciphersuite = to_ciphersuite(obj.cipher_suite)?;
                let kat_transcript = kat_transcripts::generate_test_vector(*ciphersuite);
                let kat_bytes = into_bytes(kat_transcript);
                ("Transcript", kat_bytes)
            }
            Ok(TestVectorType::Treekem) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "OpenMLS currently can't generate TreeKEM test vectors. See GitHub issue #423 for more information.",
                ));
            }
            Ok(TestVectorType::Messages) => {
                let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
                let kat_messages = kat_messages::generate_test_vector(ciphersuite);
                let kat_bytes = into_bytes(kat_messages);
                ("Messages", kat_bytes)
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        let response = GenerateTestVectorResponse { test_vector };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");
        let backend = &OpenMlsRustCrypto::default();

        let obj = request.get_ref();
        let (type_msg, _result) = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => {
                write("mlspp_treemath.json", &obj.test_vector);
                let kat_treemath = match serde_json::from_slice(&obj.test_vector) {
                    Ok(test_vector) => test_vector,
                    Err(_) => {
                        return Err(tonic::Status::new(
                            tonic::Code::InvalidArgument,
                            "Couldn't decode treemath test vector.",
                        ));
                    }
                };
                match kat_treemath::run_test_vector(kat_treemath) {
                    Ok(result) => ("Tree math", result),
                    Err(e) => {
                        let message = "Error while running treemath test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Encryption) => {
                let kat_encryption: EncryptionTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode encryption test vector.",
                            ));
                        }
                    };
                write(
                    &format!(
                        "mlspp_encryption_{}_{}.json",
                        kat_encryption.cipher_suite, kat_encryption.n_leaves
                    ),
                    &obj.test_vector,
                );
                match kat_encryption::run_test_vector(kat_encryption, backend) {
                    Ok(result) => ("Encryption", result),
                    Err(e) => {
                        let message = "Error while running encryption test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::KeySchedule) => {
                let kat_key_schedule: KeyScheduleTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode key schedule test vector.",
                            ));
                        }
                    };
                write(
                    &format!("mlspp_key_schedule_{}.json", kat_key_schedule.cipher_suite),
                    &obj.test_vector,
                );
                match kat_key_schedule::run_test_vector(kat_key_schedule, backend) {
                    Ok(result) => ("Key Schedule", result),
                    Err(e) => {
                        let message = "Error while running key schedule test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Transcript) => {
                let kat_transcript: TranscriptTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            println!("{}", String::from_utf8_lossy(&obj.test_vector));
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode transcript test vector.",
                            ));
                        }
                    };
                write(
                    &format!("mlspp_transcript_{}.json", kat_transcript.cipher_suite),
                    &obj.test_vector,
                );
                match kat_transcripts::run_test_vector(kat_transcript, backend) {
                    Ok(result) => ("Transcript", result),
                    Err(e) => {
                        let message = "Error while running transcript test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Ok(TestVectorType::Treekem) => {
                todo!("#624: See TreeKEM is currently not working. See https://github.com/openmls/openmls/issues/624");
                // let kat_tree_kem: TreeKemTestVector = match serde_json::from_slice(&obj.test_vector)
                // {
                //     Ok(test_vector) => test_vector,
                //     Err(_) => {
                //         return Err(tonic::Status::new(
                //             tonic::Code::InvalidArgument,
                //             "Couldn't decode TreeKEM test vector.",
                //         ));
                //     }
                // };
                // write(
                //     &format!("mlspp_tree_kem_{}.json", kat_tree_kem.cipher_suite),
                //     &obj.test_vector,
                // );
                // match kat_tree_kem::run_test_vector(kat_tree_kem, backend) {
                //     Ok(result) => ("TreeKEM", result),
                //     Err(e) => {
                //         let message = "Error while running TreeKEM test vector: ".to_string()
                //             + &e.to_string();
                //         return Err(tonic::Status::new(tonic::Code::Aborted, message));
                //     }
                // }
            }
            Ok(TestVectorType::Messages) => {
                let kat_messages: MessagesTestVector =
                    match serde_json::from_slice(&obj.test_vector) {
                        Ok(test_vector) => test_vector,
                        Err(_) => {
                            return Err(tonic::Status::new(
                                tonic::Code::InvalidArgument,
                                "Couldn't decode messages test vector.",
                            ));
                        }
                    };
                write("mlspp_messages_{}.json", &obj.test_vector);
                match kat_messages::run_test_vector(kat_messages) {
                    Ok(result) => ("Messages", result),
                    Err(e) => {
                        let message = "Error while running messages test vector: ".to_string()
                            + &e.to_string();
                        return Err(tonic::Status::new(tonic::Code::Aborted, message));
                    }
                }
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::Unimplemented,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request successful", type_msg);

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let create_group_request = request.get_ref();

        let ciphersuite = Ciphersuite::try_from(create_group_request.cipher_suite as u16).unwrap();
        let credential_bundle = CredentialBundle::new(
            "OpenMLS".bytes().collect(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            &self.crypto_provider,
        )
        .unwrap();
        let key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite],
            &credential_bundle,
            &self.crypto_provider,
            vec![],
        )
        .unwrap();
        let kp_hash = key_package_bundle
            .key_package()
            .hash_ref(self.crypto_provider.crypto())
            .unwrap();
        self.crypto_provider
            .key_store()
            .store(kp_hash.value(), &key_package_bundle)
            .unwrap();
        let wire_format_policy = wire_format_policy(create_group_request.encrypt_handshake);
        let mls_group_config = MlsGroupConfig::builder()
            .wire_format_policy(wire_format_policy)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &self.crypto_provider,
            &mls_group_config,
            GroupId::from_slice(&create_group_request.group_id),
            kp_hash.as_slice(),
        )
        .map_err(into_status)?;

        let interop_group = InteropGroup {
            credential_bundle,
            wire_format_policy,
            group,
            own_kpbs: Vec::new(),
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

        let ciphersuite = to_ciphersuite(create_kp_request.cipher_suite)?;
        let credential_bundle = CredentialBundle::new(
            "OpenMLS".bytes().collect(),
            CredentialType::Basic,
            ciphersuite.signature_algorithm(),
            &self.crypto_provider,
        )
        .unwrap();
        let key_package_bundle = KeyPackageBundle::new(
            &[*ciphersuite],
            &credential_bundle,
            &self.crypto_provider,
            vec![],
        )
        .unwrap();
        let key_package = key_package_bundle.key_package().clone();
        let mut transaction_id_map = self.transaction_id_map.lock().unwrap();
        let transaction_id = transaction_id_map.len() as u32;
        transaction_id_map.insert(
            transaction_id,
            key_package
                .hash_ref(self.crypto_provider.crypto())
                .unwrap()
                .value()
                .to_vec(),
        );

        self.pending_key_packages.lock().unwrap().insert(
            key_package_bundle
                .key_package()
                .hash_ref(self.crypto_provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            (key_package_bundle, credential_bundle),
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
        let (_kpb, credential_bundle) = welcome
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
            credential_bundle,
            wire_format_policy,
            group,
            own_kpbs: Vec::new(),
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

        let state_auth_secret = interop_group.group.authentication_secret();

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
            .create_message(&self.crypto_provider, &protect_request.application_data)
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
        let unverified_message = interop_group
            .group
            .parse_message(message, &self.crypto_provider)
            .map_err(into_status)?;
        let processed_message = interop_group
            .group
            .process_unverified_message(unverified_message, None, &self.crypto_provider)
            .map_err(into_status)?;
        let application_data = match processed_message {
            ProcessedMessage::ApplicationMessage(application_message) => {
                application_message.into_bytes()
            }
            ProcessedMessage::ProposalMessage(_) => unreachable!(),
            ProcessedMessage::StagedCommitMessage(_) => unreachable!(),
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
            .propose_add_member(&self.crypto_provider, &key_package)
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
        let key_package_bundle = KeyPackageBundle::new(
            &[interop_group.group.ciphersuite()],
            &interop_group.credential_bundle,
            &self.crypto_provider,
            vec![],
        )
        .unwrap();
        let mls_group_config = MlsGroupConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(interop_group.wire_format_policy)
            .build();
        interop_group.group.set_configuration(&mls_group_config);
        let proposal = interop_group
            .group
            .propose_self_update(&self.crypto_provider, Some(key_package_bundle.clone()))
            .map_err(into_status)?
            .to_bytes()
            .unwrap();

        interop_group.own_kpbs.push(key_package_bundle);

        Ok(Response::new(ProposalResponse { proposal }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let remove_proposal_request = request.get_ref();

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
            .propose_remove_member(
                &self.crypto_provider,
                &KeyPackageRef::from_slice(&remove_proposal_request.removed),
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

    async fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
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

        // Proposals by reference. These proposals are standalone proposals. They should be appended to the proposal store.

        for proposal in &commit_request.by_reference {
            let message = MlsMessageIn::tls_deserialize(&mut proposal.as_slice())
                .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
            let unverified_message = interop_group
                .group
                .parse_message(message, &self.crypto_provider)
                .map_err(into_status)?;
            let processed_message = interop_group
                .group
                .process_unverified_message(unverified_message, None, &self.crypto_provider)
                .map_err(into_status)?;
            match processed_message {
                ProcessedMessage::ApplicationMessage(_) => unreachable!(),
                ProcessedMessage::ProposalMessage(proposal) => {
                    interop_group.group.store_pending_proposal(*proposal);
                }
                ProcessedMessage::StagedCommitMessage(_) => unreachable!(),
            }
        }

        // Proposals by value. These proposals are inline proposals. They should be converted into group operations.

        // TODO #692: The interop client cannot process these proposals yet.

        let (commit, welcome_option) = interop_group
            .group
            .self_update(&self.crypto_provider, None)
            .map_err(into_status)?;

        let commit = commit.to_bytes().unwrap();

        let welcome = if let Some(welcome) = welcome_option {
            welcome
                .tls_serialize_detached()
                .map_err(|_| Status::aborted("failed to serialize welcome"))?
        } else {
            vec![]
        };

        Ok(Response::new(CommitResponse { commit, welcome }))
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
            let unverified_message = interop_group
                .group
                .parse_message(message, &self.crypto_provider)
                .map_err(into_status)?;
            let processed_message = interop_group
                .group
                .process_unverified_message(unverified_message, None, &self.crypto_provider)
                .map_err(into_status)?;
            match processed_message {
                ProcessedMessage::ApplicationMessage(_) => unreachable!(),
                ProcessedMessage::ProposalMessage(proposal) => {
                    interop_group.group.store_pending_proposal(*proposal);
                }
                ProcessedMessage::StagedCommitMessage(_) => unreachable!(),
            }
        }

        let message = MlsMessageIn::tls_deserialize(&mut handle_commit_request.commit.as_slice())
            .map_err(|_| Status::aborted("failed to deserialize ciphertext"))?;
        let unverified_message = interop_group
            .group
            .parse_message(message, &self.crypto_provider)
            .map_err(into_status)?;
        let processed_message = interop_group
            .group
            .process_unverified_message(unverified_message, None, &self.crypto_provider)
            .map_err(into_status)?;
        match processed_message {
            ProcessedMessage::ApplicationMessage(_) => unreachable!(),
            ProcessedMessage::ProposalMessage(_) => unreachable!(),
            ProcessedMessage::StagedCommitMessage(_) => {
                interop_group
                    .group
                    .merge_pending_commit()
                    .map_err(into_status)?;
            }
        }

        Ok(Response::new(HandleCommitResponse {
            state_id: handle_commit_request.state_id,
        }))
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
