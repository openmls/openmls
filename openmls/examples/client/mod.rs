use openmls::group::{GroupId, MlsGroup};
use std::collections::HashMap;

struct Client {
    groups: HashMap<GroupId, MlsGroup>,
}
