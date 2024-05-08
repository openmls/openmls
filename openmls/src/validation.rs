//! # Validation
//!
//! This module implements all validation steps for MLS.
//!
//! ## Design principle
//!
//! To ensure that all checks are implemented, a struct needs to ensure that these
//! checks have been performed, BEFORE it is being constructed.

use crate::{
    group::{past_secrets::MessageSecretsStore, PublicGroup, ValidationError},
    prelude::{mls_auth_content_in::VerifiableAuthenticatedContentIn, ProtocolMessage, Sender},
};

type ValidationResult = Result<(), ValidationError>;
