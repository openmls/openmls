# GREASE Support

GREASE (Generate Random Extensions And Sustain Extensibility) is a mechanism defined in [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5) to ensure that implementations properly handle unknown values and maintain protocol extensibility.

## What is GREASE?

GREASE values are special reserved values that follow a specific pattern (`0x0A0A, 0x1A1A, 0x2A2A, ..., 0xEAEA`) and are used to:

1. **Test extensibility**: Ensure implementations don't reject messages containing unknown values
2. **Prevent ossification**: Help maintain forward compatibility by exercising unknown value handling paths
3. **Identify bugs**: Catch implementations that incorrectly assume all possible values are known

## GREASE in OpenMLS

OpenMLS automatically handles GREASE values for the following types:

- **Ciphersuites** (`VerifiableCiphersuite`)
- **Extensions** (`ExtensionType::Grease`)
- **Proposals** (`ProposalType::Grease`)
- **Credentials** (`CredentialType::Grease`)

### Automatic Handling

OpenMLS automatically:

1. **Recognizes GREASE values** during deserialization
2. **Filters GREASE values** during validation to prevent false negatives
3. **Preserves GREASE values** when present in capabilities

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

### Generating Random GREASE Values

OpenMLS provides a helper function to generate random GREASE values:

```rust
use openmls::grease::random_grease_value;
use openmls_rust_crypto::OpenMlsRustCrypto;

let crypto = OpenMlsRustCrypto::default();
let grease_value = random_grease_value(&crypto);

// Use in capabilities
let grease_proposal = ProposalType::Grease(grease_value);
```

### Checking for GREASE Values

All GREASE-capable types provide an `is_grease()` method:

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

Here's a complete example showing GREASE usage:

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

// Create capabilities with GREASE values
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

// The KeyPackage can be used normally - GREASE values are automatically handled
```

## Further Reading

- [RFC 9420 Section 13.5: GREASE](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5)
- [RFC 8701: Applying GREASE to TLS Extensibility](https://www.rfc-editor.org/rfc/rfc8701.html) - The original GREASE specification for TLS

