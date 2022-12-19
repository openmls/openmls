# External Types

For interoperability, this crate also defines several types and algorithm
identifiers.

**AEADs**

The following AEADs are defined.

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:12:21}}
```

An AEAD provides the following functions to get the according values for each
algorithm.

- `tag_size`
- `key_size`
- `nonce_size`

**Hashing**

The following hash algorithms are defined.

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:54:58}}
```

A hash algorithm provides the following functions to get the according values for each
algorithm.

- `size`

**Signatures**

The following signature schemes are defined.

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:89:100}}
```

# HPKE Types

The HPKE implementation is part of the crypto provider as well.
The crate, therefore, defines the necessary types too.

The HPKE algorithms are defined as follows.

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:163:178}}
```

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:183:192}}
```

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:197:209}}
```

In addition, helper structs for `HpkeCiphertext` and `HpkeKeyPair` are defined.

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:222:225}}
```

```rust,no_run,noplayground
{{#include ../../../traits/src/types.rs:229:232}}
```
