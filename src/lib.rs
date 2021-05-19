//! A rust re-implementation of the Python library [`itsdangerous`].
//!
//! Essentially, this crate provides various helpers to pass data to untrusted environments
//! and get it back safe and sound. Data is cryptographically signed to ensure that it has
//! not been tampered with.
//!
//! ## Signers
//!
//! * [`Signer`], a signer that signs/unsigns arbitrary values.
//! * [`TimestampSigner`], a signer that signs/unsigns arbitrary values attaching a signed
//!   timestamp so  you know when the value was signed.
//!
//! ## Basic Example
//! ```rust
//! use std::time::Duration;
//! use itsdangerous::{default_builder, Signer};
//!
//! // Create a signer using the default builder, and an arbitrary secret key.
//! let signer = default_builder("secret key").build();
//!
//! // Sign an arbitrary string, and send it somewhere dangerous.
//! let signed = signer.sign("hello world!");
//!
//! // Unsign the string and validate that it hasn't been tampered with.
//! let unsigned = signer.unsign(&signed).expect("Signature was not valid");
//! assert_eq!(unsigned, "hello world!");
//! ```
//!
//! [`itsdangerous`]: https://github.com/pallets/itsdangerous/

#![cfg_attr(feature = "nightly", feature(test))]

// TODO: One day un-comment this.
// #![warn(missing_docs)]

mod base64;
mod error;
mod separator;
mod signer;
mod timed;
mod timestamp;
mod traits;

pub mod algorithm;
pub mod key_derivation;

#[cfg(feature = "serializer")]
mod multi_serializer;
#[cfg(feature = "serializer")]
mod serde_serializer;
#[cfg(feature = "serializer")]
mod serializer_traits;

pub use error::{
    BadSignature, BadTimedSignature, InvalidSeparator, PayloadError, TimestampExpired,
};
pub use separator::Separator;
pub use signer::{default_builder, DefaultSigner, SignerBuilder};
pub use timed::{DefaultTimestampSigner, UnsignedValue};
pub use traits::{AsSigner, IntoTimestampSigner, Signer, TimestampSigner};

#[cfg(feature = "serializer")]
pub use multi_serializer::MultiSerializer;
#[cfg(feature = "serializer")]
pub use serde_serializer::{
    serializer_with_signer, timed_serializer_with_signer, NullEncoding, URLSafeEncoding,
    UnsignedTimedSerializerValue, UnverifiedTimedValue, UnverifiedValue,
};
#[cfg(feature = "serializer")]
pub use serializer_traits::{Encoding, Serializer, TimedSerializer};
