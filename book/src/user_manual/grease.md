# GREASE Support

GREASE (Generate Random Extensions And Sustain Extensibility) is a mechanism defined in [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5) to ensure that implementations properly handle unknown values and maintain protocol extensibility.

## What is GREASE?

GREASE values are special reserved values that follow a specific pattern (`0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA`) and are used to:

1. **Test extensibility**: Ensure implementations don't reject messages containing unknown values
2. **Prevent ossification**: Help maintain forward compatibility by exercising unknown value handling paths
3. **Identify bugs**: Catch implementations that incorrectly assume all possible values are known

### RFC-defined vs. Custom GREASE Values

The [15 values defined in RFC 9420](#grease-values) are the "official" GREASE values. When OpenMLS generates GREASE values (e.g., via `with_grease()`), it uses these RFC-defined values. The `is_grease()` method only returns `true` for these specific values.

However, **any** unknown value can serve a similar purpose. The difference is that for non-RFC values, we cannot distinguish whether they are intentionally injected "GREASE-like" values or genuinely unknown identifiers from future protocol extensions.

### The Purpose of GREASE

**Important:** The entire point of GREASE is that implementations should **not** check for these values. GREASE values exist to ensure that your unknown-value handling code paths are exercised. Applications can inject GREASE values into their capabilities to discourage other implementations from:

- Failing on unknown values
- Hard-coding assumptions about which values exist
- Breaking when the protocol is extended

See [Important Notes](#important-notes) for details on how OpenMLS handles GREASE during validation.

## GREASE in OpenMLS

OpenMLS supports GREASE values for the following types:

- **Ciphersuites** (`VerifiableCiphersuite`)
- **Extensions** (`ExtensionType::Grease`)
- **Proposals** (`ProposalType::Grease`)
- **Credentials** (`CredentialType::Grease`)

### GREASE Handling

OpenMLS:

1. **Recognizes GREASE values** during deserialization
2. **Filters GREASE values** during validation to prevent false negatives (GREASE values are treated the same as unknown values)
3. **Preserves GREASE values** when present in capabilities
4. **Provides convenience methods** to inject random GREASE values into capabilities

**Note:** GREASE values are NOT automatically injected. Library users who wish to include GREASE values in their capabilities should use the `with_grease()` method described below.

## Using GREASE Values

### In Capabilities

You can include GREASE values in your KeyPackage capabilities to test interoperability:

```rust
use openmls::prelude::*;

let capabilities = Capabilities::builder()
    .proposals(vec![
        ProposalType::Add,
        ProposalType::Update,
        ProposalType::Remove,
        ProposalType::Grease(0x0A0A), // Add a GREASE proposal type
    ])
    .extensions(vec![
        ExtensionType::ApplicationId,
        ExtensionType::Grease(0x1A1A), // Add a GREASE extension type
    ])
    .credentials(vec![
        CredentialType::Basic,
        CredentialType::Grease(0x2A2A), // Add a GREASE credential type
    ])
    .build();
```

### Injecting Random GREASE Values

The easiest way to add GREASE values is using the `with_grease()` method on `Capabilities` or `CapabilitiesBuilder`:

```rust
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

let provider = OpenMlsRustCrypto::default();

// Using CapabilitiesBuilder
let capabilities = Capabilities::builder()
    .with_grease(provider.rand())
    .build();

// Or on an existing Capabilities instance
let capabilities = Capabilities::default()
    .with_grease(provider.rand());
```

This will add one random GREASE value to each capability list (ciphersuites, extensions, proposals, and credentials) if no GREASE value is already present.

### Generating Individual Random GREASE Values

OpenMLS also provides a helper function to generate individual random GREASE values:

```rust
use openmls::grease::random_grease_value;
use openmls_rust_crypto::OpenMlsRustCrypto;

let crypto = OpenMlsRustCrypto::default();
let grease_value = random_grease_value(&crypto);

// Use in capabilities
let grease_proposal = ProposalType::Grease(grease_value);
```

### Checking for GREASE Values

All GREASE-capable types provide an `is_grease()` method. Note that this method only identifies the [RFC-defined GREASE values](#grease-values)—it cannot detect custom unknown values that serve a similar purpose.

**Caution:** As explained in [The Purpose of GREASE](#the-purpose-of-grease), applications should generally **not** use `is_grease()` for filtering or decision-making. The method exists primarily for OpenMLS's internal validation logic and for testing/debugging purposes.

```rust
use openmls::prelude::*;

let proposal = ProposalType::Grease(0x0A0A);
assert!(proposal.is_grease());

let extension = ExtensionType::Grease(0x1A1A);
assert!(extension.is_grease());

let credential = CredentialType::Grease(0x2A2A);
assert!(credential.is_grease());

use openmls_traits::types::VerifiableCiphersuite;
let ciphersuite = VerifiableCiphersuite::new(0x3A3A);
assert!(ciphersuite.is_grease());
```

## GREASE Values

The following 15 values are defined as GREASE values in RFC 9420:

- `0x0A0A`
- `0x1A1A`
- `0x2A2A`
- `0x3A3A`
- `0x4A4A`
- `0x5A5A`
- `0x6A6A`
- `0x7A7A`
- `0x8A8A`
- `0x9A9A`
- `0xAAAA`
- `0xBABA`
- `0xCACA`
- `0xDADA`
- `0xEAEA`

## Important Notes

### GREASE Values Cannot Be Used for Operations

GREASE ciphersuites, in particular, cannot be used for actual cryptographic operations. They exist only to test capability negotiation and should never be selected as the active ciphersuite for a group.

### Validation Automatically Filters GREASE

When OpenMLS validates capabilities, it automatically filters out GREASE values. This means:

- Two members with different GREASE values in their capabilities can still interoperate
- GREASE values don't affect capability intersection or matching
- Required capabilities never include GREASE values

### Interoperability Testing

Including GREASE values in your capabilities is recommended for testing interoperability with other MLS implementations. It helps ensure that:

1. Other implementations correctly handle unknown values
2. Your implementation correctly filters GREASE during validation
3. Protocol extensibility is maintained

## Example: Full Usage

Here's a complete example showing GREASE usage with the recommended `with_grease()` method:

```rust
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;

let provider = OpenMlsRustCrypto::default();

// Create a credential
let credential = BasicCredential::new(b"Alice".to_vec());
let signature_keys = SignatureKeyPair::new(
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm()
).unwrap();

// Create capabilities with automatic random GREASE values
let capabilities = Capabilities::builder()
    .with_grease(provider.rand())
    .build();

// Create a KeyPackage with GREASE values
let key_package = KeyPackage::builder()
    .leaf_node_capabilities(capabilities)
    .build(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        &provider,
        &signature_keys,
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
    )
    .unwrap();

// The KeyPackage can be used normally - GREASE values are handled during validation
```

### Example: Manually Specifying GREASE Values

If you need to specify particular GREASE values (e.g., for testing or interoperability):

```rust
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;

let provider = OpenMlsRustCrypto::default();

// Create a credential
let credential = BasicCredential::new(b"Alice".to_vec());
let signature_keys = SignatureKeyPair::new(
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm()
).unwrap();

// Create capabilities with specific GREASE values
let capabilities = Capabilities::builder()
    .proposals(vec![
        ProposalType::Add,
        ProposalType::Update,
        ProposalType::Remove,
        ProposalType::Grease(0x0A0A),
        ProposalType::Grease(0x1A1A),
    ])
    .extensions(vec![
        ExtensionType::ApplicationId,
        ExtensionType::Grease(0x2A2A),
    ])
    .credentials(vec![
        CredentialType::Basic,
        CredentialType::Grease(0x3A3A),
    ])
    .build();

// Create a KeyPackage with these capabilities
let key_package = KeyPackage::builder()
    .leaf_node_capabilities(capabilities)
    .build(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        &provider,
        &signature_keys,
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
    )
    .unwrap();
```

## Further Reading

- [RFC 9420 Section 13.5: GREASE](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5)
- [RFC 8701: Applying GREASE to TLS Extensibility](https://www.rfc-editor.org/rfc/rfc8701.html) - The original GREASE specification for TLS

