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

#[macro_use]
extern crate criterion;
extern crate maelstrom;
extern crate rand;

use criterion::Criterion;
use maelstrom::creds::*;
use maelstrom::crypto::aead::*;
use maelstrom::crypto::dh::*;
use maelstrom::crypto::hash::*;
use maelstrom::crypto::hkdf::*;
use maelstrom::crypto::hmac::*;
use maelstrom::crypto::hpke::*;
use maelstrom::extensions::*;
use maelstrom::kp::*;
use maelstrom::utils::*;

const DATA: &[u8; 1024] = &[1u8; 1024];

// Crypto

fn criterion_hash(c: &mut Criterion) {
    c.bench_function("Hash SHA256", |b| {
        b.iter(|| {
            let _prk_h = hash(HashAlgorithm::SHA256, DATA);
        });
    });
    c.bench_function("Hash SHA512", |b| {
        b.iter(|| {
            let _prk_h = hash(HashAlgorithm::SHA512, DATA);
        });
    });
}

fn criterion_hkdf(c: &mut Criterion) {
    const ALGORITHM: HMACAlgorithm = HMACAlgorithm::SHA256;
    c.bench_function("HKDF extract", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        b.iter(|| {
            let _prk = extract(ALGORITHM, &salt, &ikm);
        });
    });
    c.bench_function("HKDF expand", |b| {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let len = 32;
        let prk = extract(ALGORITHM, &salt, &ikm);
        b.iter(|| {
            let _okm = expand(ALGORITHM, &prk, DATA, len);
        });
    });
}

fn criterion_aes_128(c: &mut Criterion) {
    c.bench_function("AES128 encrypt", |b| {
        let algorithm = AEADAlgorithm::AES128GCM;
        let key = AEADKey::from_slice(algorithm, &randombytes(AES128KEYBYTES)).unwrap();
        let nonce = Nonce::new_random();
        let data = &randombytes(1_000);
        let aad = &randombytes(1_000);
        b.iter(|| {
            let _encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
        });
    });
    c.bench_function("AES128 decrypt", |b| {
        let algorithm = AEADAlgorithm::AES128GCM;
        let aad = &randombytes(1_000);
        b.iter_with_setup(
            || {
                let key = AEADKey::from_slice(algorithm, &randombytes(AES128KEYBYTES)).unwrap();
                let nonce = Nonce::new_random();
                let data = &randombytes(1_000);
                let encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
                (key, nonce, encrypted, aad)
            },
            |(key, nonce, encrypted, aad)| {
                let _decrypted = aead_open(algorithm, &encrypted, aad, &key, &nonce).unwrap();
            },
        )
    });
}

fn criterion_aes_256(c: &mut Criterion) {
    c.bench_function("AES256 encrypt", |b| {
        let algorithm = AEADAlgorithm::AES256GCM;
        let key = AEADKey::from_slice(algorithm, &randombytes(AES256KEYBYTES)).unwrap();
        let nonce = Nonce::new_random();
        let data = &randombytes(1_000);
        let aad = &randombytes(1_000);
        b.iter(|| {
            let _encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
        });
    });
    c.bench_function("AES256 decrypt", |b| {
        let algorithm = AEADAlgorithm::AES256GCM;
        let aad = &randombytes(1_000);
        b.iter_with_setup(
            || {
                let key = AEADKey::from_slice(algorithm, &randombytes(AES256KEYBYTES)).unwrap();
                let nonce = Nonce::new_random();
                let data = &randombytes(1_000);
                let encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
                (key, nonce, encrypted, aad)
            },
            |(key, nonce, encrypted, aad)| {
                let _decrypted = aead_open(algorithm, &encrypted, aad, &key, &nonce).unwrap();
            },
        )
    });
}

fn criterion_chacha(c: &mut Criterion) {
    c.bench_function("ChaCha20Poly1305 encrypt", |b| {
        let algorithm = AEADAlgorithm::CHACHA20POLY1305;
        let key = AEADKey::from_slice(algorithm, &randombytes(CHACHAKEYBYTES)).unwrap();
        let nonce = Nonce::new_random();
        let data = &randombytes(1_000);
        let aad = &randombytes(1_000);
        b.iter(|| {
            let _encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
        });
    });
    c.bench_function("ChaCha20Poly1305 decrypt", |b| {
        let algorithm = AEADAlgorithm::CHACHA20POLY1305;
        let aad = &randombytes(1_000);
        b.iter_with_setup(
            || {
                let key = AEADKey::from_slice(algorithm, &randombytes(CHACHAKEYBYTES)).unwrap();
                let nonce = Nonce::new_random();
                let data = &randombytes(1_000);
                let encrypted = aead_seal(algorithm, data, aad, &key, &nonce).unwrap();
                (key, nonce, encrypted, aad)
            },
            |(key, nonce, encrypted, aad)| {
                let _decrypted = aead_open(algorithm, &encrypted, aad, &key, &nonce).unwrap();
            },
        )
    });
}

fn criterion_hpke(c: &mut Criterion) {
    c.bench_function("HPKE gen key", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
        b.iter(|| DHKeyPair::new(ciphersuite.into()).unwrap())
    });
    c.bench_function("HPKE encrypt", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
        let kp = DHKeyPair::new(ciphersuite.into()).unwrap();
        b.iter(|| {
            let _ = HpkeCiphertext::seal(ciphersuite, &kp.public_key, DATA, None, None).unwrap();
        });
    });
    c.bench_function("HPKE decrypt", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
        let kp = DHKeyPair::new(ciphersuite.into()).unwrap();
        let encrypted =
            HpkeCiphertext::seal(ciphersuite, &kp.public_key, DATA, None, None).unwrap();
        b.iter(|| {
            let _decrypted = encrypted
                .open(ciphersuite, &kp.private_key, None, None)
                .unwrap();
        });
    });
}
fn criterion_ed25519(c: &mut Criterion) {
    c.bench_function("Ed25519 gen key", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
        b.iter(|| Identity::new(ciphersuite, vec![1, 2, 3]))
    });
    c.bench_function("Ed25519 sign", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let identity = Identity::new(ciphersuite, vec![1, 2, 3]);
        b.iter(|| {
            let _ = identity.sign(DATA);
        });
    });
    c.bench_function("Ed25519 verify", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let identity = Identity::new(ciphersuite, vec![1, 2, 3]);
        let signature = identity.sign(DATA);
        b.iter(|| {
            identity.verify(DATA, &signature);
        });
    });
}

fn criterion_kp_bundle(c: &mut Criterion) {
    c.bench_function("KeyPackage create bundle", |b| {
        let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519;
        b.iter_with_setup(
            || Identity::new(ciphersuite, vec![1, 2, 3]),
            |identity| KeyPackageBundle::new(ciphersuite, &identity, None),
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_hash(c);
    criterion_hkdf(c);
    criterion_hpke(c);
    criterion_chacha(c);
    criterion_aes_128(c);
    criterion_aes_256(c);
    criterion_ed25519(c);
    criterion_kp_bundle(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
