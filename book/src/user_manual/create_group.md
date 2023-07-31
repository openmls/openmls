# Creating groups

Before a group can be created, a group configuration (`MlsGroupConfiguration`) needs to be defined. The default values of configuration parameters are picked for safety. However, check all parameters carefully to ascertain if they match your implementation's requirements. See [Group configuration](group_config.md) for more details.

In addition to the group configuration, the client should define all supported and required extensions for the group. The negotiation mechanism for extension in MLS consists in setting an initial list of extensions at group creation time and choosing key packages of subsequent new members accordingly.

In practice, the supported and required extensions are set by adding them to the initial `KeyPackage` of the creator:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_key_package}}
```

After that, the group can be created:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group}}
```

Note: Every group is assigned a random group ID during creation. The group ID cannot be changed and remains immutable throughout the group's lifetime. Choosing it randomly makes sure that the group ID doesn't collide with any other group ID in the same system.

If someone else already gave you a group ID, e.g., a provider server, you can also create a group using a specific group ID:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group_with_group_id}}
```
