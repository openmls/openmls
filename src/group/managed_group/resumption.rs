use super::*;

/// Resumption secrets store. This is where the resumption secrets are kept in a rollover list.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ResumptionSecretStore {
    number_of_secrets: usize,
    resumption_secrets: Vec<(GroupEpoch, ResumptionSecret)>,
    cursor: usize,
}

impl ResumptionSecretStore {
    /// Create e new store with a given maximum size of `number_of_secrets`.
    pub(crate) fn new(number_of_secrets: usize) -> Self {
        Self {
            number_of_secrets,
            resumption_secrets: vec![],
            cursor: 0,
        }
    }

    /// Add a new entry to the store.
    pub(crate) fn add(&mut self, epoch: GroupEpoch, resumption_secret: ResumptionSecret) {
        if self.number_of_secrets == 0 {
            return;
        }
        let item = (epoch, resumption_secret);
        if self.resumption_secrets.len() < self.number_of_secrets {
            self.resumption_secrets.push(item);
            self.cursor += 1;
        } else {
            self.cursor += 1;
            self.cursor %= self.resumption_secrets.len();
            self.resumption_secrets[self.cursor] = item;
        }
    }

    /// Find an entry for a give epoch number and optionally return the corresponding secret.
    pub(crate) fn get(&self, epoch: GroupEpoch) -> Option<&ResumptionSecret> {
        self.resumption_secrets
            .iter()
            .find(|&(e, _s)| e == &epoch)
            .map(|(_e, s)| s)
    }
}
