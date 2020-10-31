// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::framing::*;

/// This tests serializing/deserializing MLSPlaintext
#[test]
fn codec() {
    use crate::ciphersuite::*;

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let credential_bundle =
        CredentialBundle::new(vec![7, 8, 9], CredentialType::Basic, ciphersuite.name()).unwrap();
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: LeafIndex::from(2u32),
    };
    let mut orig = MLSPlaintext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        sender,
        authenticated_data: vec![1, 2, 3],
        content_type: ContentType::Application,
        content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
        signature: Signature::new_empty(),
    };
    let context = GroupContext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        tree_hash: vec![],
        confirmed_transcript_hash: vec![],
    };
    let serialized_context = context.encode_detached().unwrap();
    let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context));
    orig.signature = signature_input.sign(&credential_bundle);

    let enc = orig.encode_detached().unwrap();
    let copy = MLSPlaintext::from_bytes(&enc).unwrap();
    assert_eq!(orig, copy);
}

/// This tests the presence of the group context in MLSPlaintextTBS
#[test]
fn context_presence() {
    use crate::ciphersuite::*;

    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential_bundle = CredentialBundle::new(
        "Random identity".into(),
        CredentialType::Basic,
        ciphersuite_name,
    )
    .unwrap();
    let sender = Sender {
        sender_type: SenderType::Member,
        sender: LeafIndex::from(2u32),
    };
    let mut orig = MLSPlaintext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        sender,
        authenticated_data: vec![1, 2, 3],
        content_type: ContentType::Application,
        content: MLSPlaintextContentType::Application(vec![4, 5, 6]),
        signature: Signature::new_empty(),
    };
    let context = GroupContext {
        group_id: GroupId::random(),
        epoch: GroupEpoch(1u64),
        tree_hash: vec![],
        confirmed_transcript_hash: vec![],
    };
    let serialized_context = context.encode_detached().unwrap();
    let signature_input = MLSPlaintextTBS::new_from(&orig, Some(serialized_context.clone()));
    orig.signature = signature_input.sign(&credential_bundle);
    assert!(orig.verify(
        Some(serialized_context.clone()),
        credential_bundle.credential()
    ));
    assert!(!orig.verify(None, credential_bundle.credential()));

    let signature_input = MLSPlaintextTBS::new_from(&orig, None);
    orig.signature = signature_input.sign(&credential_bundle);
    assert!(!orig.verify(Some(serialized_context), credential_bundle.credential()));
    assert!(orig.verify(None, credential_bundle.credential()));
}
