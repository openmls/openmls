# Signature Keys for the Basic Credential

The basic credential in the MLS spec is only defined by its identity.
In practice the basic credential needs a key pair for signatures to be functional.
This crate implements a simple signature key pair for basic credential and
implements the `Signer` trait required by the OpenMLS APIs.
