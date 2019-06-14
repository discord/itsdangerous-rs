use std::time::SystemTime;

use generic_array::ArrayLength;
use typenum::Unsigned;

use crate::algorithm::{Signature, Signer as AlgorithmSigner};
use crate::error::BadSignature;
use crate::{BadTimedSignature, Seperator, UnsignedValue};

pub trait Signer {
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
