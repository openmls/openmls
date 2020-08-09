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

use crate::codec::*;
use crate::crypto::aead::*;
use crate::crypto::dh::*;
use crate::crypto::hkdf;
use crate::extensions::*;
use crate::utils::*;
use byteorder::{BigEndian, WriteBytesExt};
use std::*;

#[derive(Debug)]
pub enum HPKEError {
    EncryptionError,
    DecryptionError,
    WrongKeyLength,
    NonceOverflow,
    AEAD(AEADError),
    Codec(CodecError),
    DH(DHError),
}

impl From<AEADError> for HPKEError {
    fn from(err: AEADError) -> HPKEError {
        HPKEError::AEAD(err)
    }
}

impl From<CodecError> for HPKEError {
    fn from(err: CodecError) -> HPKEError {
        HPKEError::Codec(err)
    }
}

impl From<DHError> for HPKEError {
    fn from(err: DHError) -> HPKEError {
        HPKEError::DH(err)
    }
}

pub type HPKEPublicKey = DHPublicKey;
pub type HPKEPrivateKey = DHPrivateKey;
pub type HPKEKeyPair = DHKeyPair;

#[derive(Debug, PartialEq, Clone)]
pub struct HpkeCiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Codec for HpkeCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.kem_output)?;
        encode_vec(VecSize::VecU16, buffer, &self.ciphertext)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let kem_output = decode_vec(VecSize::VecU16, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU16, cursor)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }
}

impl HpkeCiphertext {
    pub fn seal(
        ciphersuite: Ciphersuite,
        public_key: &DHPublicKey,
        payload: &[u8],
        aad: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<HpkeCiphertext, HPKEError> {
        let (enc, mut context) = setup_base_s(ciphersuite, public_key, info.unwrap_or(&[]));
        let ciphertext = context.seal(aad.unwrap_or(&[]), payload)?;
        Ok(HpkeCiphertext {
            kem_output: enc,
            ciphertext,
        })
    }
    pub fn open(
        &self,
        ciphersuite: Ciphersuite,
        skr: &DHPrivateKey,
        aad: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<Vec<u8>, HPKEError> {
        let mut context = setup_base_r(ciphersuite, &self.kem_output, skr, info.unwrap_or(&[]));
        context.open(aad.unwrap_or(&[]), &self.ciphertext)
    }
}

pub struct AEADContext {
    ciphersuite: Ciphersuite,
    key: Vec<u8>,
    nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    seq: u64,
}

impl AEADContext {
    pub fn new(
        ciphersuite: Ciphersuite,
        key: Vec<u8>,
        nonce: Vec<u8>,
        exporter_secret: Vec<u8>,
    ) -> Self {
        AEADContext {
            ciphersuite,
            key,
            nonce,
            exporter_secret,
            seq: 0,
        }
    }
    pub fn nonce(&self, seq: u64) -> Vec<u8> {
        // encSeq = encode_big_endian(seq, Nn)
        // return xor(self.nonce, encSeq)
        let enq_sec = encode_big_endian(seq, nn(self.ciphersuite));
        xor(&self.nonce, &enq_sec)
    }
    pub fn increment_seq(&mut self) -> Result<(), HPKEError> {
        // if self.seq >= (1 << Nn) - 1:
        // return NonceOverflowError
        // self.seq += 1
        if self.seq >= (1 << nn(self.ciphersuite)) - 1 {
            return Err(HPKEError::NonceOverflow);
        }
        self.seq += 1;
        Ok(())
    }
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HPKEError> {
        // ct = Seal(self.key, self.Nonce(self.seq), aad, pt)
        // self.IncrementSeq()
        // return ct
        let ct = aead_seal(
            self.ciphersuite.into(),
            pt,
            aad,
            &AEADKey::from_slice(self.ciphersuite.into(), &self.key)?,
            &Nonce::from_slice(&self.nonce(self.seq))?,
        )?;
        self.increment_seq()?;
        Ok(ct)
    }
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, HPKEError> {
        // pt = Open(self.key, self.Nonce(self.seq), aad, ct)
        // if pt == OpenError:
        // return OpenError
        // self.IncrementSeq()
        // return pt
        let pt = aead_open(
            self.ciphersuite.into(),
            ct,
            aad,
            &AEADKey::from_slice(self.ciphersuite.into(), &self.key)?,
            &Nonce::from_slice(&self.nonce(self.seq))?,
        )?;
        self.increment_seq()?;
        Ok(pt)
    }
    pub fn export(&self, exporter_context: &[u8], l: usize) -> Vec<u8> {
        // return LabeledExpand(self.exporter_secret, "sec", exporter_context, L)
        labeled_expand(
            self.ciphersuite,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            l,
        )
    }
}

fn nk(ciphersuite: Ciphersuite) -> usize {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 16,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 16,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 32,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 32,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 32,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 32,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

fn nn(ciphersuite: Ciphersuite) -> usize {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 12,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 12,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 12,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 12,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 12,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 12,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum HPKEMode {
    ModeBase = 0,
    ModePSK = 1,
    ModeAuth = 2,
    ModeAuthPSK = 3,
}

/*
def KeySchedule(mode, zz, info, psk, pskID, pkSm):
     VerifyMode(mode, psk, pskID, pkSm)

     ciphersuite = concat(encode_big_endian(kem_id, 2),
                          encode_big_endian(kdf_id, 2),
                          encode_big_endian(aead_id, 2))
     pskID_hash = LabeledExtract(zero(Nh), "pskID_hash", pskID)
     info_hash = LabeledExtract(zero(Nh), "info", info)
     context = concat(ciphersuite, mode, pskID_hash, info_hash)

     psk = LabeledExtract(zero(Nh), "psk_hash", psk)

     secret = LabeledExtract(psk, "zz", zz)
     key = LabeledExpand(secret, "key", context, Nk)
     nonce = LabeledExpand(secret, "nonce", context, Nn)
     exporter_secret = LabeledExpand(secret, "exp", context, Nh)

     return Context(key, nonce, exporter_secret)

*/

fn key_schedule(
    ciphersuite: Ciphersuite,
    mode: HPKEMode,
    zz: &[u8],
    info: &[u8],
    psk: Option<&[u8]>,
    psk_id: Option<&[u8]>,
) -> AEADContext {
    let nh = shared_secret_length(ciphersuite.into());
    let hpke_ciphersuite = concat(&[
        encode_u16(kem_id(ciphersuite)),
        encode_u16(kdf_id(ciphersuite)),
        encode_u16(aead_id(ciphersuite)),
    ]);
    let psk_id_hash = labeled_extract(ciphersuite, &zero(nh), b"pskID_hash", psk_id.unwrap_or(&[]));
    let info_hash = labeled_extract(ciphersuite, &zero(nh), b"info", info);
    let context = concat(&[hpke_ciphersuite, vec![mode as u8], psk_id_hash, info_hash]);

    let psk_hash = labeled_extract(
        ciphersuite,
        &zero(nh),
        b"psk_hash",
        psk.unwrap_or(&zero(nh)),
    );

    let secret = labeled_extract(ciphersuite, &psk_hash, b"zz", zz);
    let key = labeled_expand(ciphersuite, &secret, b"key", &context, nk(ciphersuite));
    let nonce = labeled_expand(ciphersuite, &secret, b"nonce", &context, nn(ciphersuite));
    let exporter_secret = labeled_expand(ciphersuite, &secret, b"exp", &context, nh);

    AEADContext::new(ciphersuite, key, nonce, exporter_secret)
}

/*
    def SetupBaseS(pkR, info):
      zz, enc = Encap(pkR)
      return enc, KeySchedule(mode_base, zz, info,
                        default_psk, default_pskID, default_pkSm)
*/

fn setup_base_s(
    ciphersuite: Ciphersuite,
    pkr: &DHPublicKey,
    info: &[u8],
) -> (Vec<u8>, AEADContext) {
    let mode = HPKEMode::ModeBase;
    let (zz, enc) = encap(ciphersuite, pkr).unwrap(); // TODO Error handling
    let aead_context = key_schedule(ciphersuite, mode, &zz, info, None, None);
    (enc, aead_context)
}

/*
    def SetupBaseR(enc, skR, info):
     zz = Decap(enc, skR)
     return KeySchedule(mode_base, zz, info,
                        default_psk, default_pskID, default_pkSm)
*/

fn setup_base_r(
    ciphersuite: Ciphersuite,
    enc: &[u8],
    skr: &DHPrivateKey,
    info: &[u8],
) -> AEADContext {
    let mode = HPKEMode::ModeBase;
    let zz = decap(ciphersuite, enc, skr).unwrap(); // TODO handle error
    key_schedule(ciphersuite, mode, &zz, info, None, None)
}

/*
    skE, pkE = GenerateKeyPair()
     dh = DH(skE, pkR)
     enc = Marshal(pkE)

     pkRm = Marshal(pkR)
     kemContext = concat(enc, pkRm)

     zz = ExtractAndExpand(dh, kemContext)
     return zz, enc
*/

fn encap(ciphersuite: Ciphersuite, pkr: &DHPublicKey) -> Result<(Vec<u8>, Vec<u8>), DHError> {
    let keypair = DHKeyPair::new(ciphersuite.into())?;
    let ske = keypair.private_key;
    let pke = keypair.public_key;
    encap_with_keypair(ciphersuite, pkr, &ske, &pke)
}

fn encap_with_keypair(
    ciphersuite: Ciphersuite,
    pkr: &DHPublicKey,
    ske: &DHPrivateKey,
    pke: &DHPublicKey,
) -> Result<(Vec<u8>, Vec<u8>), DHError> {
    let dh = ske.shared_secret(pkr)?;
    let enc = pke.as_slice();
    let pkrm = pkr.as_slice();
    let kem_context = concat(&[enc.clone(), pkrm]);
    let zz = extract_and_expand(ciphersuite, &dh, &kem_context);
    Ok((zz, enc))
}
/*
    def Decap(enc, skR):
     pkE = Unmarshal(enc)
     dh = DH(skR, pkE)

     pkRm = Marshal(pk(skR))
     kemContext = concat(enc, pkRm)

     zz = ExtractAndExpand(dh, kemContext)
     return zz

*/

fn decap(ciphersuite: Ciphersuite, enc: &[u8], skr: &DHPrivateKey) -> Result<Vec<u8>, DHError> {
    let pke = DHPublicKey::from_slice(enc, ciphersuite.into())?;
    let dh = skr.shared_secret(&pke)?;
    let pkrm = skr.derive_public_key().unwrap().as_slice(); // TODO improve performance by passing keypair
    let kem_context = concat(&[enc.to_vec(), pkrm]);
    let zz = extract_and_expand(ciphersuite, &dh, &kem_context);
    Ok(zz)
}

/*
    def ExtractAndExpand(dh, kemContext):
     prk = LabeledExtract(zero(Nh), "dh", dh)
     return LabeledExpand(prk, "prk", kemContext, Nzz)
*/

fn extract_and_expand(ciphersuite: Ciphersuite, dh: &[u8], kem_context: &[u8]) -> Vec<u8> {
    let prk = labeled_extract(
        ciphersuite,
        &zero(shared_secret_length(ciphersuite.into())),
        b"dh",
        dh,
    );
    labeled_expand(ciphersuite, &prk, b"prk", kem_context, nzz(ciphersuite))
}

/*
    def LabeledExtract(salt, label, IKM):
     labeledIKM = concat("RFCXXXX ", label, IKM)
     return Extract(salt, labeledIKM)
*/

fn labeled_extract(ciphersuite: Ciphersuite, salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let labeled_ikm = concat(&[b"RFCXXXX ".to_vec(), label.to_vec(), ikm.to_vec()]);
    hkdf::extract(ciphersuite.into(), salt, &labeled_ikm)
}

/*
   def LabeledExpand(PRK, label, info, L):
     labeledInfo = concat(encode_big_endian(L, 2),
                           "RFCXXXX ", label, info)
     return Expand(PRK, labeledInfo, L)
*/

fn labeled_expand(
    ciphersuite: Ciphersuite,
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    l: usize,
) -> Vec<u8> {
    let labeled_info = concat(&[
        encode_u16(l as u16),
        b"RFCXXXX ".to_vec(),
        label.to_vec(),
        info.to_vec(),
    ]);
    hkdf::expand(ciphersuite.into(), prk, &labeled_info, l).unwrap()
}

fn nzz(ciphersuite: Ciphersuite) -> usize {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 32,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 32,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 32,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 64,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 64,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 64,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

fn kem_id(ciphersuite: Ciphersuite) -> u16 {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 0x0010,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 0x0020,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 0x0020,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 0x0012,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 0x0021,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 0x0021,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

fn kdf_id(ciphersuite: Ciphersuite) -> u16 {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 0x0001,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 0x0001,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 0x0001,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 0x0003,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 0x0003,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 0x0003,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

fn aead_id(ciphersuite: Ciphersuite) -> u16 {
    match ciphersuite {
        Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => 0x0001,
        Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => 0x0001,
        Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => 0x0003,
        Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => 0x0002,
        Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => 0x0002,
        Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => 0x0003,
        Ciphersuite::Default => panic!("Invalid ciphersuite"),
    }
}

fn encode_u16(value: u16) -> Vec<u8> {
    (value as u16).encode_detached().unwrap()
}

fn concat(values: &[Vec<u8>]) -> Vec<u8> {
    values.join(&[][..])
}

fn encode_big_endian(value: u64, length: usize) -> Vec<u8> {
    let mut buffer = vec![];
    buffer.write_u64::<BigEndian>(value).unwrap();
    if length > buffer.len() {
        let padding_length = length - buffer.len();
        let mut padding_bytes = zero(padding_length);
        padding_bytes.append(&mut buffer);
        buffer = padding_bytes
    }
    buffer
}

fn xor(slice1: &[u8], slice2: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    for (v1, v2) in slice1.iter().zip(slice2) {
        result.push(*v1 ^ *v2);
    }
    result
}

#[test]
fn encap_decap() {
    let ciphersuite = Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
    let algorithm = DHAlgorithm::X25519;
    let keypair = DHKeyPair::new(algorithm).unwrap();
    let (zz1, enc) = encap(ciphersuite, &keypair.public_key).unwrap();
    let zz2 = decap(ciphersuite, &enc, &keypair.private_key).unwrap();
    assert_eq!(zz1, zz2);
}

#[test]
fn hpke_seal_open_x25519_aes() {
    let ciphersuite = Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
    let kp = DHKeyPair::new(ciphersuite.into()).unwrap();
    let cleartext = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let encrypted =
        HpkeCiphertext::seal(ciphersuite, &kp.public_key, &cleartext, None, None).unwrap();
    let decrypted = encrypted
        .open(ciphersuite, &kp.private_key, None, None)
        .unwrap();

    assert_eq!(cleartext, decrypted);
}

#[test]
fn hpke_seal_open_x25519_chacha_random() {
    use crate::utils::*;
    for _ in 0..10 {
        let ciphersuite = Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let kp = DHKeyPair::new(ciphersuite.into()).unwrap();
        let cleartext = randombytes(1000);

        let encrypted =
            HpkeCiphertext::seal(ciphersuite, &kp.public_key, &cleartext, None, None).unwrap();
        let decrypted = encrypted
            .open(ciphersuite, &kp.private_key, None, None)
            .unwrap();

        assert_eq!(cleartext, decrypted);
    }
}

#[test]
fn hpke_test_vectors() {
    use crate::utils::*;

    /*
    mode: 0
    kemID: 32
    kdfID: 1
    aeadID: 1
    info: 4f6465206f6e2061204772656369616e2055726e
    skR: d3c8ca6516cd4cc75f66210c5a49d05381bfbfc0de090c19432d778ea4599829
    skE: b9d453d3ec0dbe59fa4a193bde3e4ea17f80c9b2fa69f2f3e029120303b86885
    pkR: 10b2fc2332b75206d2c791c3db1094dfd298b6508138ce98fec2c0c7a4dbc408
    pkE: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
    enc: 07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33
    zz: 79f0c71200a133c4e608a1d2dab5830e54ba7ee71abd6522cfc4af6ad1c47ac2
    context: 002000010001005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce02570cf993d1b24564499e3cec2bd4e7128a963d96f013c353992d27115c0a2ab771af17d02c2528ef3c
             002000010001005D0F5548CB13D7EBA5320AE0E21B1EE274AAC7EA1CCE02570CF993D1B24564499E3CEC2BD4E7128A963D96F013C353992D27115C0A2AB771AF17D02C2528EF3C
    secret: e7a85117b9cac58c508eeb153faab0a8205a73d4fca1bb7b81d1a4b504eb71f8
            FAF23372F67F31690A35388EAA36F2F17C3618460D7C9806375A93F255CF2007
    key: ab86480a0094bfe110fca55d98dccafd
    nonce: 4a5fc401e6551f69db44d64d
    exporterSecret:
    eb9570b621c3894a182c40ee67ed9d71bcfb114e2315b2ceaaade6454fa21291
    */

    let ciphersuite = Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
    assert_eq!(kem_id(ciphersuite), 32);
    assert_eq!(kdf_id(ciphersuite), 1);
    assert_eq!(aead_id(ciphersuite), 1);
    let mode = HPKEMode::ModeBase;
    let skr = DHPrivateKey::from_slice(
        &hex_to_bytes("d3c8ca6516cd4cc75f66210c5a49d05381bfbfc0de090c19432d778ea4599829"),
        ciphersuite.into(),
    )
    .unwrap();
    let pkr = DHPublicKey::from_slice(
        &hex_to_bytes("10b2fc2332b75206d2c791c3db1094dfd298b6508138ce98fec2c0c7a4dbc408"),
        ciphersuite.into(),
    )
    .unwrap();
    let ske = DHPrivateKey::from_slice(
        &hex_to_bytes("b9d453d3ec0dbe59fa4a193bde3e4ea17f80c9b2fa69f2f3e029120303b86885"),
        ciphersuite.into(),
    )
    .unwrap();
    let pke = DHPublicKey::from_slice(
        &hex_to_bytes("07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33"),
        ciphersuite.into(),
    )
    .unwrap();

    let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e");
    let expected_zz =
        hex_to_bytes("79f0c71200a133c4e608a1d2dab5830e54ba7ee71abd6522cfc4af6ad1c47ac2");
    let expected_enc =
        hex_to_bytes("07da186c37d11e92d924fd1a75aff87d11860dfd59ea940429d8b874de846a33");

    /*
    sequence number: 0
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d30
    nonce: 4a5fc401e6551f69db44d64d
    ciphertext: 1ae0fe213b0c230f723d057a9476a5e95e9348699aec1ecfe67bd67a69cb63894b5aed52332059289c44c4a69e
    */

    let sequence_number: u64 = 0;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d30");
    let expected_nonce = hex_to_bytes("4a5fc401e6551f69db44d64d");
    let expected_ciphertext = hex_to_bytes("1ae0fe213b0c230f723d057a9476a5e95e9348699aec1ecfe67bd67a69cb63894b5aed52332059289c44c4a69e");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 1
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d31
    nonce: 4a5fc401e6551f69db44d64c
    ciphertext: 00e8cec1e413913e942a214fd0d610fdcbe53285491d4e7bbfff51c11b401c9e150cac56757e074d923d0de840
    */

    let sequence_number: u64 = 1;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d31");
    let expected_nonce = hex_to_bytes("4a5fc401e6551f69db44d64c");
    let expected_ciphertext = hex_to_bytes("00e8cec1e413913e942a214fd0d610fdcbe53285491d4e7bbfff51c11b401c9e150cac56757e074d923d0de840");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 2
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d32
    nonce: 4a5fc401e6551f69db44d64f
    ciphertext: 244862294f4036de67304d9f24da1079f4f914c8ffc768999065c657dda40c0572c0d04e70d72cf3d150e4bf74
    */

    let sequence_number: u64 = 2;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d32");
    let expected_nonce = hex_to_bytes("4a5fc401e6551f69db44d64f");
    let expected_ciphertext = hex_to_bytes("244862294f4036de67304d9f24da1079f4f914c8ffc768999065c657dda40c0572c0d04e70d72cf3d150e4bf74");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 4
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d34
    nonce: 4a5fc401e6551f69db44d649
    ciphertext: 4acf4661c93dc673a6d6372167f2a356c13e430e61a84ebc1919bf26dbc7d0132c7a54f9698094ddae52ac8e8f
    */

    let sequence_number: u64 = 4;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d34");
    let expected_nonce = hex_to_bytes("4a5fc401e6551f69db44d649");
    let expected_ciphertext = hex_to_bytes("4acf4661c93dc673a6d6372167f2a356c13e430e61a84ebc1919bf26dbc7d0132c7a54f9698094ddae52ac8e8f");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    mode: 0
    kemID: 32
    kdfID: 1
    aeadID: 3
    info: 4f6465206f6e2061204772656369616e2055726e
    skR: 0a2737d281922bdd223db035c4c0b4154179f338e20dd45b3cb6e801bc078229
    skE: 43f15e4141a3532e03d5b974ab4dae83c8e3b460ab0ecdfb5b38451ef35ade1f
    pkR: cd965e8af97e58598b02ebaef2d376e430a7a744fe64b58ac37c0ad8a026dc02
    pkE: 0298cbf0d065c0c4d5fad9367fdae4350d2ca07b66936c70f9d8a61a64271707
    enc: 0298cbf0d065c0c4d5fad9367fdae4350d2ca07b66936c70f9d8a61a64271707
    zz: fd311e3b861d9ce5ddb89a37bd5b76f5d08f50a10ce4499ffe8aa8934e7222bf
    context: 002000010003005d0f5548cb13d7eba5320ae0e21b1ee274aac7ea1cce02570
    cf993d1b24564499e3cec2bd4e7128a963d96f013c353992d27115c0a2ab771af17d02c2
    528ef3c
    secret: faf0773568a55c251d1d9590e88f8464fa544271c178f90f4c177e9cfaad152a
    key: 954b77e7b3e5db38142f19cda6ace6948e154aa2bc1a193ac90f89565364512c
    nonce: f49ff6240b6d611a2bf9af90
    exporterSecret:
    2e9eb4e338775bc70dd4f5bf1b6f2d0d4565472456cc8b70baa631841e6085e2
    */

    let ciphersuite = Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
    assert_eq!(kem_id(ciphersuite), 32);
    assert_eq!(kdf_id(ciphersuite), 1);
    assert_eq!(aead_id(ciphersuite), 3);
    let mode = HPKEMode::ModeBase;
    let skr = DHPrivateKey::from_slice(
        &hex_to_bytes("0a2737d281922bdd223db035c4c0b4154179f338e20dd45b3cb6e801bc078229"),
        ciphersuite.into(),
    )
    .unwrap();
    let pkr = DHPublicKey::from_slice(
        &hex_to_bytes("cd965e8af97e58598b02ebaef2d376e430a7a744fe64b58ac37c0ad8a026dc02"),
        ciphersuite.into(),
    )
    .unwrap();
    let ske = DHPrivateKey::from_slice(
        &hex_to_bytes("43f15e4141a3532e03d5b974ab4dae83c8e3b460ab0ecdfb5b38451ef35ade1f"),
        ciphersuite.into(),
    )
    .unwrap();
    let pke = DHPublicKey::from_slice(
        &hex_to_bytes("0298cbf0d065c0c4d5fad9367fdae4350d2ca07b66936c70f9d8a61a64271707"),
        ciphersuite.into(),
    )
    .unwrap();

    let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e");
    let expected_zz =
        hex_to_bytes("fd311e3b861d9ce5ddb89a37bd5b76f5d08f50a10ce4499ffe8aa8934e7222bf");
    let expected_enc =
        hex_to_bytes("0298cbf0d065c0c4d5fad9367fdae4350d2ca07b66936c70f9d8a61a64271707");

    /*
    sequence number: 0
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d30
    nonce: f49ff6240b6d611a2bf9af90
    ciphertext: 744b9a6332791b799d6f2160697bf2c127df9a0bd35e708ea3d0e165b0f1180fe9f7a863b7624f14584c6d12c8
    */

    let sequence_number: u64 = 0;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d30");
    let expected_nonce = hex_to_bytes("f49ff6240b6d611a2bf9af90");
    let expected_ciphertext = hex_to_bytes("744b9a6332791b799d6f2160697bf2c127df9a0bd35e708ea3d0e165b0f1180fe9f7a863b7624f14584c6d12c8");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 1
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d31
    nonce: f49ff6240b6d611a2bf9af91
    ciphertext: 7f95fb427ec720e03f5b9f29b56f9f78c065ac3538469ecdb9672cb2a077d7d42ff85f9ed7e58bfbf14502b1a1
    */

    let sequence_number: u64 = 1;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d31");
    let expected_nonce = hex_to_bytes("f49ff6240b6d611a2bf9af91");
    let expected_ciphertext = hex_to_bytes("7f95fb427ec720e03f5b9f29b56f9f78c065ac3538469ecdb9672cb2a077d7d42ff85f9ed7e58bfbf14502b1a1");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 2
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d32
    nonce: f49ff6240b6d611a2bf9af92
    ciphertext: 143f13b9130768a2f31c418b251cd2320ce0ab25eeb711894f57fa5468baac30a89af146db36506d80ff15f687
    */

    let sequence_number: u64 = 2;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d32");
    let expected_nonce = hex_to_bytes("f49ff6240b6d611a2bf9af92");
    let expected_ciphertext = hex_to_bytes("143f13b9130768a2f31c418b251cd2320ce0ab25eeb711894f57fa5468baac30a89af146db36506d80ff15f687");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    /*
    sequence number: 4
    plaintext: 4265617574792069732074727574682c20747275746820626561757479
    aad: 436f756e742d34
    nonce: f49ff6240b6d611a2bf9af94
    ciphertext: 6231544225e67367b0384da833d4c286ae1cf752ef87eb7511e9c1d3c94c97df03e0dbebd4d3dd74c753e4bd11
    */

    let sequence_number: u64 = 4;
    let plaintext = hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex_to_bytes("436f756e742d34");
    let expected_nonce = hex_to_bytes("f49ff6240b6d611a2bf9af94");
    let expected_ciphertext = hex_to_bytes("6231544225e67367b0384da833d4c286ae1cf752ef87eb7511e9c1d3c94c97df03e0dbebd4d3dd74c753e4bd11");

    test_vector(
        ciphersuite,
        &skr,
        &pkr,
        &ske,
        &pke,
        mode,
        &info,
        &aad,
        None,
        None,
        sequence_number,
        &plaintext,
        &expected_enc,
        &expected_nonce,
        &expected_ciphertext,
        &expected_zz,
    );

    #[allow(clippy::too_many_arguments)]
    fn test_vector(
        ciphersuite: Ciphersuite,
        skr: &DHPrivateKey,
        pkr: &DHPublicKey,
        ske: &DHPrivateKey,
        pke: &DHPublicKey,
        mode: HPKEMode,
        info: &[u8],
        aad: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sequence_number: u64,
        plaintext: &[u8],
        expected_enc: &[u8],
        expected_nonce: &[u8],
        expected_ciphertext: &[u8],
        expected_zz: &[u8],
    ) {
        let (zz, enc) = encap_with_keypair(ciphersuite, &pkr, &ske, &pke).unwrap(); // TODO Error handling
        assert_eq!(zz, expected_zz);
        assert_eq!(enc, expected_enc);

        let mut aead_context_seal = key_schedule(ciphersuite, mode, &zz, &info, psk, psk_id);
        assert_eq!(aead_context_seal.nonce(sequence_number), expected_nonce);
        aead_context_seal.seq = sequence_number;

        let ciphertext = aead_context_seal.seal(&aad, &plaintext).unwrap();
        assert_eq!(ciphertext, expected_ciphertext);

        let zz = decap(ciphersuite, &enc, &skr).unwrap();
        let mut aead_context_open = key_schedule(ciphersuite, mode, &zz, &info, None, None);
        aead_context_open.seq = sequence_number;
        let pt = aead_context_open.open(&aad, &ciphertext).unwrap();
        assert_eq!(pt, plaintext);
    }
}
