# Security Policy

OpenMLS is an implementation of the Messaging Layer Security (MLS) protocol
([RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420)). This document
explains what we treat as a security vulnerability, what is out of scope, and
how to report an issue to us privately.

## Scope

This policy covers the `openmls` library crate. If you find issues in any of the other crates, please file a regular GitHub issue.

## Threat model

We evaluate reports against the MLS threat model described in RFC 9420. Assume
an adversary that can:

- observe, drop, reorder, replay, and inject any network traffic, and
- control the delivery service that relays messages.

A report qualifies if it demonstrates a problem within this model.

## What we consider a security vulnerability

We treat a bug as a security vulnerability if it falls into either of the
following categories.

### 1. Bugs that threaten a core MLS security guarantee

Any bug that lets the adversary above break one of the guarantees MLS is meant
to provide:

- **Confidentiality**: message contents and group secrets stay unreadable to
  non-members and to the delivery service.
- **Authenticity**: a recipient can verify who sent a message and that its
  contents were not altered, including authenticity of group membership and
  group state changes.
- **Group key agreement**: honest members derive the same keys and agree on the
  same membership and group state, with no unauthorized or inconsistent state
  transitions.
- **Forward secrecy**: compromise of current key material does not expose
  messages or secrets from earlier epochs.
- **Post-compromise security**: after a member is compromised, the group
  recovers its security once that member performs an update and all other group
  members receive it.

A report that shows any of these can be violated, or that OpenMLS accepts input
it should reject (or rejects input it should accept) in a way that leads to such
a violation, is a security vulnerability.

### 2. Panics and other crashes reachable from untrusted input before authentication

Any panic, abort, unbounded memory or CPU consumption, or other crash that an
attacker can trigger with crafted input before that input has been
authenticated is a security vulnerability, because it enables remote denial of
service. This covers the paths that run before signature and membership
verification, for example wire-format decoding and parsing of key packages,
welcome messages, group info, and protocol messages.

## What is not a security vulnerability

The following are handled as ordinary issues, not through this policy:

- Bugs in application code that uses OpenMLS, or in cryptographic providers or
  storage backends that are not maintained in this repository.
- Attacks that require breaking an underlying cryptographic primitive, for
  example, forging a signature without the signing key.
- Behavior that concerns a property MLS does not claim to provide, for example
  metadata that RFC 9420 exposes to the delivery service by design.
- Panics or incorrect results only reachable from input the application itself
  supplies and trusts, or from using the API in a way its documentation tells
  you not to.
- Findings outside of the main `openmls` crate. We fix these on a best-effort basis and they are not covered by the coordinated disclosure process.
- Suggestions for hardening or defense in depth that do not come with a concrete
  security impact.

If you are unsure whether something qualifies, report it privately and let us
assess it.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue,
pull request, or discussion, and do not disclose the issue publicly until we
have published a fix.

Instead, use GitHub private vulnerability reporting. Go to the [Security tab](https://github.com/openmls/openmls/security) of the repository and click "Report a vulnerability". This opens a private draft advisory that only the maintainers and people we add can see.

Please include enough for us to reproduce and assess the issue:

- the affected crate and version or commit,
- a description of the problem and which guarantee or crash it concerns,
- a proof of concept or the minimal steps and input that trigger it,
- the observed behavior and the impact you believe it has, and
- your platform and toolchain if it is relevant.

## Recognition

With your agreement, we credit reporters in the published advisory and release
notes. Let us know how you would like to be named, or if you prefer to remain
anonymous.

## Good-faith research

We will not pursue or support action against anyone who reports a vulnerability
in good faith under this policy, as long as they avoid privacy violations, data
destruction, and disruption of others' services while researching, and give us a
reasonable chance to fix the issue before disclosing it publicly.


