# Using Additional Authenticated Data (AAD)

The Additional Authenticated Data (AAD) is a byte sequence that can be included in both private and public messages. By design, it is always authenticated (signed) but never encrypted. Its purpose is to contain data that can be inspected but not changed while a message is in transit.

## Setting the AAD

Members can set the AAD by calling the  `.set_aad()` function. The AAD will remain set until the next API call that successfully generates an `MlsMessageOut`. Until then, the AAD can be inspected with the `.aad()` function.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:set_aad}}
```

## Inspecting the AAD

Members can inspect the AAD of an incoming message once the message has been processed. The AAD can be accessed with the `.aad()` function of a `ProcessedMessage`.

```rust,no_run,noplayground
{{#include ../../../openmls/tests/book_code.rs:inspect_aad}}
```

