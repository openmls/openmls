# Creating groups

There are two ways to create a group: Either by building an `MlsGroup` directly, or by using an `MlsGroupCreateConfig`. The former is slightly simpler, while the latter allows the creating of multiple groups using the same configuration. See [Group configuration](./group_config.md) for more details on group parameters.

In addition to the group configuration, the client should define all supported and required extensions for the group. The negotiation mechanism for extension in MLS consists in setting an initial list of extensions at group creation time and choosing key packages of subsequent new members accordingly.

In practice, the supported and required extensions are set by adding them to the initial `KeyPackage` of the creator:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:create_key_package}}
```

After that, the group can be created either using a config:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group}}
```

... or using the builder pattern:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group_with_builder}}
```

Note: Every group is assigned a random group ID during creation. The group ID cannot be changed and remains immutable throughout the group's lifetime. Choosing it randomly makes sure that the group ID doesn't collide with any other group ID in the same system.

If someone else already gave you a group ID, e.g., a provider server, you can also create a group using a specific group ID:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group_with_group_id}}
```

The Builder provides methods for setting required capabilities and external senders.
The information passed into these lands in the group context, in the form of extensions.
Should the user want to add further extensions, they can use the `with_group_context_extensions` method:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:alice_create_group_with_builder_with_extensions}}
```
