use std::time::{Duration, SystemTime};
use std::{error, fmt, str};

use crate::base64;
use crate::Separator;

#[derive(Debug)]
pub enum PayloadError {
    #[cfg(feature = "serializer")]
    Serde(serde_json::Error),
    Base64(base64::DecodeError),
    Utf8Error(str::Utf8Error),
}

#[derive(Debug)]
pub struct SeparatorNotFound {
    pub separator: Separator,
}

/// Errors that can occur while unsigning a "signed value".
#[derive(Debug)]
pub enum BadSignature<'a> {
    /// A string was provided to unsign, but it did not contain
    /// the expected separator.
    SeparatorNotFound { separator: Separator },
    /// The signature did not match what we expected it to be.
    SignatureMismatch { signature: &'a str, value: &'a str },
    /// The payload is invalid, e.g. it cannot be parsed.
    PayloadInvalid { value: &'a str, error: PayloadError },
}

/// Errors that can occur while unsigning a "signed value" using the timed signer.
#[derive(Debug)]
pub enum BadTimedSignature<'a> {
    /// A string was provided to unsign, but it did not contain
    /// the expected separator.
    SeparatorNotFound { separator: Separator },
    /// The signature did not match what we expected it to be.
    SignatureMismatch { signature: &'a str, value: &'a str },
    /// The payload is invalid, e.g. it cannot be parsed.
    PayloadInvalid { value: &'a str, error: PayloadError },
    /// The timestamp is missing, but the value was signed with a correct
    /// secret key + salt.
    TimestampMissing { value: &'a str },
    /// The timestamp was present and signed, but we weren't able to parse it back to
    /// a SystemTime.
    TimestampInvalid { timestamp: &'a str },
    /// The timestamp expired - meaning that it was more than `max_age` ago.
    TimestampExpired {
        timestamp: SystemTime,
        max_age: Duration,
        value: &'a str,
    },
}

pub struct TimestampExpired<T> {
    pub timestamp: SystemTime,
    pub max_age: Duration,
    pub value: T,
}

/// Error that occurs when trying to construct a Separator with
/// a char is in the base64 url-safe alphabet.
#[derive(Debug)]
pub struct InvalidSeparator(pub char);

impl<'a> fmt::Display for BadSignature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BadSignature::SeparatorNotFound { separator } => {
                write!(f, "Separator {:?} not found in value.", separator.0)
            }
            BadSignature::SignatureMismatch { signature, .. } => {
                write!(f, "Signature {:?} does not match.", signature)
            }
            BadSignature::PayloadInvalid { error, .. } => {
                write!(f, "Payload cannot be parsed because {:?}.", error)
            }
        }
    }
}

impl<'a> error::Error for BadSignature<'a> {
    fn description(&self) -> &str {
        match *self {
            BadSignature::SeparatorNotFound { .. } => "separator not found",
            BadSignature::SignatureMismatch { .. } => "signature does not match",
            BadSignature::PayloadInvalid { .. } => "payload invalid",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl<'a> fmt::Display for BadTimedSignature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BadTimedSignature::SeparatorNotFound { separator, .. } => {
                write!(f, "Separator {:?} not found in value.", separator.0)
            }
            BadTimedSignature::SignatureMismatch { signature, .. } => {
                write!(f, "Signature {:?} does not match.", signature)
            }
            BadTimedSignature::PayloadInvalid { error, .. } => {
                write!(f, "Payload cannot be parsed because {:?}.", error)
            }
            BadTimedSignature::TimestampMissing { .. } => write!(f, "Timestamp missing"),
            BadTimedSignature::TimestampInvalid { timestamp } => {
                write!(f, "Timestamp {:?} is invalid", timestamp)
            }
            BadTimedSignature::TimestampExpired {
                timestamp, max_age, ..
            } => write!(
                f,
                "Timestamp {:?} is older than {:?} and is expired.",
                timestamp, max_age
            ),
        }
    }
}

impl<'a> error::Error for BadTimedSignature<'a> {
    fn description(&self) -> &str {
        match *self {
            BadTimedSignature::SeparatorNotFound { .. } => "separator not found",
            BadTimedSignature::SignatureMismatch { .. } => "signature does not match",
            BadTimedSignature::TimestampMissing { .. } => "timestamp missing",
            BadTimedSignature::TimestampInvalid { .. } => "timestamp invalid",
            BadTimedSignature::TimestampExpired { .. } => "timestamp expired",
            BadTimedSignature::PayloadInvalid { .. } => "payload invalid",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl<'a> From<BadSignature<'a>> for BadTimedSignature<'a> {
    fn from(bad_signature: BadSignature<'a>) -> Self {
        match bad_signature {
            BadSignature::SeparatorNotFound { separator } => {
                BadTimedSignature::SeparatorNotFound { separator }
            }
            BadSignature::SignatureMismatch { signature, value } => {
                BadTimedSignature::SignatureMismatch { signature, value }
            }
            BadSignature::PayloadInvalid { error, value } => {
                BadTimedSignature::PayloadInvalid { error, value }
            }
        }
    }
}

impl fmt::Display for InvalidSeparator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Separator {:?} is in the base64 alphabet, and thus cannot be used",
            self.0
        )
    }
}

impl error::Error for InvalidSeparator {
    fn description(&self) -> &str {
        "invalid separator"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl fmt::Display for SeparatorNotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Separator {:?} not found in value.", self.separator)
    }
}

impl error::Error for SeparatorNotFound {
    fn description(&self) -> &str {
        "separator not foundr"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl<'a> From<SeparatorNotFound> for BadSignature<'a> {
    fn from(error: SeparatorNotFound) -> Self {
        BadSignature::SeparatorNotFound {
            separator: error.separator,
        }
    }
}

impl<'a> From<SeparatorNotFound> for BadTimedSignature<'a> {
    fn from(error: SeparatorNotFound) -> Self {
        BadTimedSignature::SeparatorNotFound {
            separator: error.separator,
        }
    }
}

impl<T> fmt::Display for TimestampExpired<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Timestamp {:?} is older than {:?} and is expired.",
            self.timestamp, self.max_age
        )
    }
}

impl<T> fmt::Debug for TimestampExpired<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TimestampExpired {{ max_age: {:?}, timestamp: {:?} }}",
            self.max_age, self.timestamp
        )
    }
}

impl<T> error::Error for TimestampExpired<T> {
    fn description(&self) -> &str {
        "timestamp expired"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl From<base64::DecodeError> for PayloadError {
    fn from(error: base64::DecodeError) -> Self {
        PayloadError::Base64(error)
    }
}

#[cfg(feature = "serializer")]
impl From<serde_json::Error> for PayloadError {
    fn from(error: serde_json::Error) -> Self {
        PayloadError::Serde(error)
    }
}

#[cfg(feature = "serializer")]
impl From<str::Utf8Error> for PayloadError {
    fn from(error: str::Utf8Error) -> Self {
        PayloadError::Utf8Error(error)
    }
}
