use std::time::SystemTime;

use generic_array::ArrayLength;
use typenum::Unsigned;

use crate::algorithm::{Signature, Signer as AlgorithmSigner};
use crate::error::BadSignature;
use crate::{BadTimedSignature, Seperator, UnsignedValue};

/// A signer can sign and unsign bytes, validating the signature provided.
///
/// A salt can be used to namespace the hash, so that a signed string is only
/// valid for a given namespace. Leaving this at the default value or re-using a salt value
/// across different parts of your application where the same signed value in one part can
/// mean something different in another part is a security risk.
///
/// # Basic Usage
/// ```rust
/// use itsdangerous::{default_builder, Signer};
///
/// // Create a signer using the default builder, and an arbitrary secret key.
/// let signer = default_builder("secret key").build();
///
/// // Sign an arbitrary string.
/// let signed = signer.sign("hello world!");
///
/// // Unsign the string and validate whether or not its expired.
/// let unsigned = signer.unsign(&signed).expect("Signature was not valid");
/// assert_eq!(unsigned, "hello world!");
/// ```
pub trait Signer {
    type TimestampSigner: TimestampSigner;

    /// Signs the given string.
    fn sign<S: AsRef<str>>(&self, value: S) -> String;

    /// Unsigns the given string. The logical inverse of [`sign`].
    ///
    /// # Remarks
    ///
    /// This method performs zero copies or heap allocations and returns a reference to a slice
    /// of the provided `value`, If you need a copy, consider doing `unsign(..).to_owned()`
    /// to convert the [`&str`] to a [`String`].
    ///
    /// [`&str`]: std::str
    /// [`sign`]: Signer::sign
    fn unsign<'a>(&'a self, value: &'a str) -> Result<&'a str, BadSignature<'a>>;

    fn seperator(&self) -> Seperator;

    /// Given a base-64 encoded signature, attempt to verify whether or not
    /// it is valid for the given `value`.
    fn verify_encoded_signature(&self, value: &[u8], encoded_signature: &[u8]) -> bool;

    /// Gets the output size in bytes of the base-64 encoded signature part that this
    /// signer will emit.
    fn signature_output_size(&self) -> usize;

    /// Converts this [`Signer`] into a [`TimestampSigner`], giving it the ability
    /// to do signing with timestamps!
    fn into_timestamp_signer(self) -> Self::TimestampSigner;
}

pub trait GetSigner {
    type OutputSize: ArrayLength<u8> + Unsigned;
    type Signer: AlgorithmSigner<OutputSize = Self::OutputSize>;

    /// Returns a signer that can be used to build a signature for a given key + values.
    fn get_signer(&self) -> Self::Signer;

    /// Returns the signature for a given key + value.
    fn get_signature(&self, value: &[u8]) -> Signature<Self::OutputSize> {
        self.get_signer().input_chained(value).sign()
    }
}

/// A TimestampSigner wraps an inner Signer, giving it the ability to dish
/// out signatures with timestamps.
///
/// # Basic Usage
/// ```rust
/// use std::time::Duration;
/// use itsdangerous::{default_builder, Signer, TimestampSigner};
///
/// // Create a signer using the default builder, and an arbitrary secret key.
/// let signer = default_builder("secret key").build().into_timestamp_signer();
///
/// // Sign an arbitrary string.
/// let signed = signer.sign("hello world!");
///
/// // Unsign the string and validate whether or not its expired.
/// let unsigned = signer.unsign(&signed).expect("Signature was not valid");
/// let value = unsigned
///     .value_if_not_expired(Duration::from_secs(60))
///     .expect("Signature was expired");
/// assert_eq!(value, "hello world!");
/// ```
pub trait TimestampSigner {
    type Signer: Signer;

    fn seperator(&self) -> Seperator {
        self.as_signer().seperator()
    }

    /// Returns a reference to the underlying [`Signer`] if you wish to use its methods.
    ///
    /// # Example
    /// ```rust
    /// use itsdangerous::{default_builder, TimestampSigner, Signer};
    ///
    /// let timestamp_signer = default_builder("hello world").build().into_timestamp_signer();
    /// let signer = timestamp_signer.as_signer();
    /// let signer = signer.sign("hello without a timestamp!");
    /// ```
    fn as_signer(&self) -> &Self::Signer;

    /// Signs a value with an arbitrary timestamp.
    fn sign_with_timestamp<S: AsRef<str>>(&self, value: S, timestamp: SystemTime) -> String;

    /// Signs a value using the current system timestamp (as provided by [`SystemTime::now`]).
    fn sign<S: AsRef<str>>(&self, value: S) -> String;

    /// The inverse of [`sign`] / [`sign_with_timestamp`], returning an [`UnsignedValue`], which you
    /// can grab the value, timestamp, and assert the max age of the signed value with.
    ///
    /// # Remarks
    ///
    /// This method performs zero copies or heap allocations and returns a reference to a slice
    /// of the provided `value`, inside of the [`UnsignedValue`] that is returned. If you need a
    /// copy, consider doing `unsigned_value.value().to_owned()` to convert the [`&str`] to a [`String`].
    ///
    /// [`&str`]: std::str
    /// [`sign`]: TimestampSigner::sign
    /// [`sign_with_timestamp`]: TimestampSigner::sign_with_timestamp
    fn unsign<'a>(&'a self, value: &'a str) -> Result<UnsignedValue, BadTimedSignature<'a>>;
}
