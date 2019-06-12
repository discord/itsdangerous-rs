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
//! use itsdangerous::default_builder;
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

// TODO: Re-enable nightly benchmarks
// #![feature(test)]

// TODO: One day un-comment this.
// #![warn(missing_docs)]

pub mod algorithm;
pub mod base64;
pub mod error;
pub mod key_derivation;
pub mod seperator;
pub mod signer;
pub mod timed;
// TODO: Feature flag.
pub mod serde_serializer;
mod timestamp;

pub use error::{
    BadSignature, BadTimedSignature, InvalidSeperator, PayloadError, TimestampExpired,
};
pub use seperator::Seperator;
pub use signer::{default_builder, Signer, SignerBuilder};
pub use timed::TimestampSigner;
