// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#[derive(Debug)]
pub enum WelcomeError {
    CiphersuiteMismatch = 100,
    JoinerSecretNotFound = 101,
    MissingRatchetTree = 102,
    TreeHashMismatch = 103,
    JoinerNotInTree = 104,
    ConfirmationTagMismatch = 105,
    InvalidRatchetTree = 106,
    InvalidGroupInfoSignature = 107,
    GroupInfoDecryptionFailure = 108,
}

#[derive(Debug)]
pub enum ApplyCommitError {
    EpochMismatch = 200,
    WrongPlaintextContentType = 201,
    SelfRemoved = 202,
    PathKeyPackageVerificationFailure = 203,
    NoParentHashExtension = 204,
    ParentHashMismatch = 205,
    PlaintextSignatureFailure = 206,
    RequiredPathNotFound = 207,
    ConfirmationTagMismatch = 208,
}

#[derive(Debug)]
pub enum CreateCommitError {
    CannotRemoveSelf = 300,
}
