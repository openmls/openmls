# Persistence of Group Data

The state of a given `MlsGroup` instance is continuously written to the configured
`StorageProvider`. Later, the `MlsGroup` can be loaded from the provider using
the `load` constructor, which can be called with the respective storage provider
as well as the `GroupId` of the group to be loaded. For this to work, the group
must have been written to the provider previously.

## Forward-Secrecy Considerations

OpenMLS uses the `StorageProvider` to store sensitive key material. To achieve forward-secrecy (i.e. to prevent an adversary from decrypting messages sent in the past if a client is compromised), OpenMLS frequently deletes previously used key material through calls to the `StorageProvider`. `StorageProvider` implementations must thus take care to ensure that values deleted through any of the `delete_` functions of the trait are irrevocably deleted and that no copies are kept.
