use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

use crate::{
    binary_tree::array_representation::TreeSize,
    ciphersuite::Secret,
    schedule::{
        pprf::{Pprf, PprfError, Prefix16},
        ApplicationExportSecret,
    },
};

pub(crate) type ApplicationExportTree = Pprf<Prefix16>;
pub(crate) type ApplicationExportTreeError = PprfError;

impl ApplicationExportTree {
    pub fn new(application_exporter: ApplicationExportSecret) -> Self {
        let size = TreeSize::from_leaf_count(u16::MAX as u32);
        Pprf::new_with_size(application_exporter.secret, size)
    }

    pub fn safe_export_secret(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        component_id: u16,
    ) -> Result<Secret, ApplicationExportTreeError> {
        self.evaluate(crypto, ciphersuite, &component_id)
    }
}
