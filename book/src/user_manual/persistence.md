# Persistence of Group Data

The state of a given `MlsGroup` instance is continuously written to the configured
`StorageProvider`. Later, the `MlsGroup` can be loaded from the provider using
the `load` constructor, which can be called with the respective storage provider
as well as the `GroupId` of the group to be loaded. For this to work, the group
must have been written to the provider previously.

## Forward-Secrecy Considerations

The persisted `MlsGroup` state contains private key material. As a consequence,
delete old group states need to be deleted in order to achieve Forward-Secrecy
w.r.t. that key material. Since, as detailed above, an old group state is stale
immediately after most group operations, we recommend that the `StorageProvider`
deletes old group state when values are overwritten.
