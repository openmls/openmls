# Persistence of Group Data

The state of a given `MlsGroup` instance can be written or read at any time using the `.save()` or `.load()` functions respectively. The functions take as input a struct implementing either the `Write` (`.save()`) or `Read` (`.load()`) trait.

Since some group operations might or might not change the `MlsGroup` state depending on the context, the group maintains the `state_changed` flag, which is set to `true` whenever the state is changed by an `MlsGroup` function. The state of the flag can be queried using the `.state_changed()` function.

## Group Lockout Upon State Loss

MLS provides strong Post-Compromise Security properties, which means that key material is regularly refreshed and old key material becomes stale very quickly. Consequently, regularly persisting state is important, especially after the client has created a commit or issued an Update proposal, thus introducing new key material into the group. A loss of state in such a situation is only recoverable in specific cases where the commit was rejected by the Delivery Service or if the proposed Update was not committed. A re-join is required in most cases to continue participating in a group after a loss of group state. To avoid a loss of state and the associated re-join, persisting `MlsGroup` state after each state-changing group operation is mandatory.

## Forward-Secrecy Considerations

The `MlsGroup` state that is persisted using the `.save()` function contains private key material. As a consequence, the application needs to delete old group states to achieve Forward-Secrecy w.r.t. that key material. Since, as detailed above, an old group state is stale immediately after most group operations, we recommend deleting old group states as soon as a new one has been written.
