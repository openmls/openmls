use crate::codec::*;

use std::error::Error;

#[derive(Debug)]
pub enum ProposalQueueError {
    ProposalNotFound,
}

implement_enum_display!(ProposalQueueError);

impl Error for ProposalQueueError {
    fn description(&self) -> &str {
        match self {
            Self::ProposalNotFound => "Not all proposals in the Commit were found locally.",
        }
    }
}

#[derive(Debug)]
pub enum ProposalOrRefTypeError {
    UnknownValue,
}

impl From<ProposalOrRefTypeError> for CodecError {
    fn from(_: ProposalOrRefTypeError) -> Self {
        CodecError::DecodingError
    }
}

implement_enum_display!(ProposalOrRefTypeError);

impl Error for ProposalOrRefTypeError {
    fn description(&self) -> &str {
        match self {
            Self::UnknownValue => "Invalid value for ProposalOrRefType was found.",
        }
    }
}

#[derive(Debug)]
pub enum QueuedProposalError {
    WrongContentType,
}

implement_enum_display!(QueuedProposalError);

impl Error for QueuedProposalError {
    fn description(&self) -> &str {
        match self {
            Self::WrongContentType => "API misuse. Only proposals can end up in the proposal queue",
        }
    }
}
