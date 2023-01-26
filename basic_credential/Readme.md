# Signature Keys for the Basic Credential

The basic credential in the MLS spec is only defined by its identity.
In order ot make MLS work a basic credential and for tests we need a signature
key pair.
This crate implements a simple signature key pair for basic credential and
implements the `Signer` trait required by the OpenMLS APIs.
