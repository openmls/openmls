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
use maelstrom::ciphersuite::*;
use maelstrom::creds::*;
use maelstrom::key_packages::*;

fn criterion_kp_bundle(c: &mut Criterion) {
    c.bench_function("KeyPackage create bundle", |b| {
        let ciphersuite =
            Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
        let signature_keypair = ciphersuite.new_signature_keypair();
        b.iter_with_setup(
            || {
                let identity = Identity::new(ciphersuite, vec![1, 2, 3]);
                Credential::Basic(BasicCredential::from(&identity))
            },
            |credential| {
                KeyPackageBundle::new(
                    &ciphersuite,
                    signature_keypair.get_private_key(),
                    credential,
                    Vec::new(),
                );
            },
        )
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_kp_bundle(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
