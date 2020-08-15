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

use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::kp::*;
use std::collections::HashMap;
pub struct Client {
    key_packages: Vec<(KeyPackage, HPKEPrivateKey)>,
    ciphersuite_config: HashMap<CiphersuiteName, (Ciphersuite, Identity)>,
}

impl Client {
    pub fn new(id: Vec<u8>, ciphersuite_names: Vec<CiphersuiteName>) -> Self {
        let mut ciphersuite_config: HashMap<CiphersuiteName, (Ciphersuite, Identity)> =
            HashMap::new();
        for cn in ciphersuite_names {
            let ciphersuite = Ciphersuite::new(cn);
            ciphersuite_config.insert(cn, (ciphersuite, Identity::new(ciphersuite, id.clone())));
        }
        Self {
            key_packages: vec![],
            ciphersuite_config,
        }
    }
    pub fn get_ciphersuite(&self, ciphersuite_name: &CiphersuiteName) -> &Ciphersuite {
        &self.ciphersuite_config.get(ciphersuite_name).unwrap().0
    }
    pub fn get_identity(&self, ciphersuite_name: &CiphersuiteName) -> &Identity {
        &self.ciphersuite_config.get(ciphersuite_name).unwrap().1
    }
}

impl Codec for Client {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        unimplemented!()
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        unimplemented!()
    }
}
