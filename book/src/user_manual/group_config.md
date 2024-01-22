# Group configuration

Two very similar structs can help configure groups upon their creation: `MlsGroupJoinConfig` and `MlsGroupCreateConfig`.

`MlsGroupJoinConfig` contains the following runtime-relevant configuration options for an `MlsGroup` and can be set on a per-client basis when a group is joined.

| Name                           | Type                            | Explanation                                                                                      |
| ------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `wire_format_policy`           | `WireFormatPolicy`              | Defines the wire format policy for outgoing and incoming handshake messages.                     |
| `padding_size`                 | `usize`                         | Size of padding in bytes. The default is 0.                                                      |
| `max_past_epochs`              | `usize`                         | Maximum number of past epochs for which application messages can be decrypted. The default is 0. |
| `number_of_resumption_psks`    | `usize`                         | Number of resumption psks to keep. The default is 0.                                             |
| `use_ratchet_tree_extension`   | `bool`                          | Flag indicating the Ratchet Tree Extension should be used. The default is `false`.               |
| `sender_ratchet_configuration` | `SenderRatchetConfiguration`    | Sender ratchet configuration.                                                                    |

`MlsGroupCreateConfig` contains an `MlsGroupJoinConfig`, as well as a few additional parameters that are part of the group state that is agreed-upon by all group members. It can be set at the time of a group's creation and contains the following additional configuration options.

| Name                           | Type                            | Explanation                                                                                      |
| ------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `group_context_extensions`     | `Extensions`                    | Optional group-level extensions, e.g. `RequiredCapabilitiesExtension`.                           |
| `capabilities` .               | `Capabilities`                  | Lists the capabilities of the group's creator.                                                   |
| `leaf_extensions` .            | `Extensions`                    | Extensions to be included in the group creator's leaf                                            |

Both ways of group configurations can be specified by using the struct's builder pattern, or choosing their default values. The default value contains safe values for all parameters and is suitable for scenarios without particular requirements.

Example join configuration:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:mls_group_config_example}}
```

Example create configuration:

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:mls_group_create_config_example}}
```

## Unknown extensions

Some extensions carry data, but don't alter the behaviour of the protocol (e.g.  the application_id extension). OpenMLS allows the use of arbitrary such extensions in the group context, key packages and leaf nodes. Such extensions can be instantiated and retrieved through the use of the `UnknownExtension` struct and the `ExtensionType::Unknown` extension type. Such "unknown" extensions are handled transparently by OpenMLS, but can be used by the application, e.g. to have a group agree on pieces of data.
