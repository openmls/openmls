use super::*;

/// Resumption psks store. This is where the resumption psks are kept in a
/// rollover list.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ResumptionPskStore {
    number_of_secrets: usize,
    resumption_psk: Vec<(GroupEpoch, ResumptionPskSecret)>,
    cursor: usize,
}

impl ResumptionPskStore {
    /// Creates a new store with a given maximum size of `number_of_secrets`.
    pub(crate) fn new(number_of_secrets: usize) -> Self {
        Self {
            number_of_secrets,
            resumption_psk: vec![],
            cursor: 0,
        }
    }

    /// Adds a new entry to the store.
    pub(crate) fn add(&mut self, epoch: GroupEpoch, resumption_psk: ResumptionPskSecret) {
        if self.number_of_secrets == 0 {
            return;
        }
        let item = (epoch, resumption_psk);
        if self.resumption_psk.len() < self.number_of_secrets {
            self.resumption_psk.push(item);
            self.cursor += 1;
        } else {
            self.cursor += 1;
            self.cursor %= self.resumption_psk.len();
            self.resumption_psk[self.cursor] = item;
        }
    }

    /// Searches an entry for a given epoch number and if found, returns the
    /// corresponding resumption psk.
    pub(crate) fn get(&self, epoch: GroupEpoch) -> Option<&ResumptionPskSecret> {
        self.resumption_psk
            .iter()
            .find(|&(e, _s)| e == &epoch)
            .map(|(_e, s)| s)
    }
}
