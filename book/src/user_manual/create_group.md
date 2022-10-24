# Creating groups

Before a group can be created, a group configuration (`MlsGroupConfiguration`) needs to be defined. The default values of configuration parameters are picked for safety. However, check all parameters carefully to ascertain if they match your implementation's requirements. See [Group configuration](group_config.md) for more details.

In addition to the group configuration, the client should define all supported and required extensions for the group. The negotiation mechanism for extension in MLS consists in setting an initial list of extensions at group creation time and choosing key packages of subsequent new members accordingly.

In practice, the supported and required extensions are set by adding them to the initial `KeyPackage` of the creator:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_key_package_bundle}}
```

Every group has a unique group ID that needs to be specified at the time of the group creation. The group ID cannot be changed after the group creation and therefore remains immutable throughout the group's lifetime. It should be chosen so that it doesn't collide with any other group IDs in the same system:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:set_group_id}}
```

After that, the group can be created:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group}}
```
