use crate::codec::*;

implement_error! {
    pub enum ProposalQueueError {
        ProposalNotFound = "Not all proposals in the Commit were found locally.",
    }
}

implement_error! {
    pub enum ProposalOrRefTypeError {
        UnknownValue = "Invalid value for ProposalOrRefType was found.",
    }
}

impl From<ProposalOrRefTypeError> for CodecError {
    fn from(_: ProposalOrRefTypeError) -> Self {
        CodecError::DecodingError
    }
}

implement_error! {
    pub enum QueuedProposalError {
        WrongContentType = "API misuse. Only proposals can end up in the proposal queue",
    }
}
