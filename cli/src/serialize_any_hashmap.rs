use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

pub(crate) fn serialize_hashmap<'a, T, U, V, S>(v: &'a V, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    U: Serialize,
    &'a V: IntoIterator<Item = (T, U)> + 'a,
    S: Serializer,
{
    let vec = v.into_iter().collect::<Vec<_>>();
    vec.serialize(serializer)
}

pub(crate) fn deserialize_hashmap<'de, T, U, D>(deserializer: D) -> Result<HashMap<T, U>, D::Error>
where
    T: Eq + std::hash::Hash + Deserialize<'de>,
    U: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Ok(Vec::<(T, U)>::deserialize(deserializer)?
        .into_iter()
        .collect::<HashMap<T, U>>())
}
