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

#[test]
fn codec() {
    use crate::ciphersuite::*;

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let keypair = ciphersuite.new_signature_keypair();
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
    orig.signature = signature_input.sign(&ciphersuite, &keypair.get_private_key());

    let enc = orig.encode_detached().unwrap();
    let copy = MLSPlaintext::from_bytes(&enc).unwrap();
    assert_eq!(orig, copy);
}

#[test]
fn context_presence() {
    use crate::ciphersuite::*;

    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let identity = Identity::new(ciphersuite, "Random identity".into());
    let credential = Credential::Basic(BasicCredential::from(&identity));
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
    orig.signature = signature_input.sign(
        &ciphersuite,
        identity.get_signature_key_pair().get_private_key(),
    );
    assert!(orig.verify(Some(serialized_context), &credential));
    assert!(!orig.verify(None, &credential));
}
