//! The error type of the session API.

use std::fmt;

/// What went wrong, coarsely. Frontends map this to a stable error code;
/// the message is for people.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Nothing is known at that address: no function, no instruction.
    NotFound,
    /// The address or range is not part of the loaded image.
    OutOfRange,
    /// The request is malformed: a bad pattern, an unknown query, a range
    /// that is empty or too large.
    InvalidInput,
    /// The binary could not be read or parsed.
    Load,
    /// Emulation could not be set up or failed to run.
    Emulation,
    /// A failure that is not the caller's doing.
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    pub fn out_of_range(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::OutOfRange, message)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, message)
    }

    pub fn load(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Load, message)
    }

    pub fn emulation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Emulation, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// For callers that only want the text.
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.message
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The message a caught panic was raised with, for turning it into an error.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else {
        "no message"
    }
}
