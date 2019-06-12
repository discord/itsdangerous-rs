use std::time::{Duration, SystemTime};

use generic_array::ArrayLength;
use typenum::Unsigned;

use crate::algorithm::{Signer as AlgorithmSigner, SigningAlgorithm};
use crate::base64::{Base64Sized, URLSafeBase64Encode};
use crate::error::BadTimedSignature;
use crate::timestamp;
use crate::{Seperator, Signer};

/// A TimestampSigner wraps an inner Signer, giving it the ability to dish
/// out signatures with timestamps.
///
/// # Basic Usage
/// ```rust
/// use std::time::Duration;
/// use itsdangerous::default_builder;
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
pub struct TimestampSigner<Algorithm, DerivedKeySize, SignatureEncoder>(
    Signer<Algorithm, DerivedKeySize, SignatureEncoder>,
)
where
    DerivedKeySize: ArrayLength<u8>;

impl<Algorithm, DerivedKeySize, SignatureEncoder>
    TimestampSigner<Algorithm, DerivedKeySize, SignatureEncoder>
where
    Algorithm: SigningAlgorithm,
    DerivedKeySize: ArrayLength<u8>,
    SignatureEncoder: Base64Sized,
{
    pub(crate) fn with_signer(signer: Signer<Algorithm, DerivedKeySize, SignatureEncoder>) -> Self {
        Self(signer)
    }

    /// Returns a reference to the underlying [`Signer`] if you wish to use its methods.
    ///
    /// # Example
    /// ```rust
    /// use itsdangerous::default_builder;
    ///
    /// let timestamp_signer = default_builder("hello world").build().into_timestamp_signer();
    /// let signer = timestamp_signer.as_signer();
    /// let signer = signer.sign("hello without a timestamp!");
    /// ```
    pub fn as_signer(&self) -> &Signer<Algorithm, DerivedKeySize, SignatureEncoder> {
        &self.0
    }

    #[inline(always)]
    pub fn seperator(&self) -> Seperator {
        self.0.seperator()
    }

    /// Signs a value with an arbitrary timestamp.
    pub fn sign_with_timestamp<S: AsRef<str>>(&self, value: S, timestamp: SystemTime) -> String {
        let value = value.as_ref();
        let encoded_timestamp = timestamp::encode(timestamp);
        let seperator = self.seperator().0;

        // Generate the signature.
        let signature = self
            .0
            .get_signer()
            .input_chained(value.as_bytes())
            .input_chained(&[seperator as u8])
            .input_chained(encoded_timestamp.as_slice())
            .sign();

        // Generate the signed output string.
        let mut output = String::with_capacity(
            value.len() + 1 + encoded_timestamp.length() + 1 + SignatureEncoder::OutputSize::USIZE,
        );

        output.push_str(value);
        output.push(seperator);
        output.push_str(encoded_timestamp.as_str());
        output.push(seperator);
        signature.base64_encode_str(&mut output);

        output
    }

    /// Signs a value using the current system timestamp (as provided by [`SystemTime::now`]).
    pub fn sign<S: AsRef<str>>(&self, value: S) -> String {
        self.sign_with_timestamp(value, SystemTime::now())
    }

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
    pub fn unsign<'a>(&'a self, value: &'a str) -> Result<UnsignedValue, BadTimedSignature<'a>> {
        // The base unsigner gives us {value}{sep}{timestamp}.
        let value = self.0.unsign(value)?;
        let (value, timestamp) = self.split(value)?;
        let timestamp = timestamp::decode(timestamp)?;

        Ok(UnsignedValue { timestamp, value })
    }

    pub(crate) fn split<'a>(
        &'a self,
        value: &'a str,
    ) -> Result<(&'a str, &'a str), BadTimedSignature<'a>> {
        // Then we split it again, to extract the value & timestamp.
        self.seperator()
            .split(value)
            .map_err(|_| BadTimedSignature::TimestampMissing { value })
    }
}

/// Represents a value + timestamp that has been successfully unsigned by [`TimestampSigner::unsign`].
pub struct UnsignedValue<'a> {
    value: &'a str,
    timestamp: SystemTime,
}

impl<'a> UnsignedValue<'a> {
    /// The value that has been [`unsigned`]. This value is safe to use and
    /// was part of a payload that has been successfully [`unsigned`].
    ///
    /// [`unsigned`]: TimestampSigner::unsign
    pub fn value(&self) -> &'a str {
        &self.value
    }

    /// The timestamp that the value was signed with.
    ///
    /// For conveniently unwrapping the value and enforcing a max age,
    /// consider using [`value_if_not_expired`].
    ///
    /// [`value_if_not_expired`]: UnsignedValue::value_if_not_expired
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Returns the value if the timestamp is not older than `max_age`.
    /// In the event that the timestamp is in the future, we'll consider that valid.
    ///
    /// If the value is expired, returns the [`BadTimedSignature::TimestampExpired`]
    /// vairant of [`BadTimedSignature`].
    pub fn value_if_not_expired(self, max_age: Duration) -> Result<&'a str, BadTimedSignature<'a>> {
        match self.timestamp.elapsed() {
            Ok(duration) if duration > max_age => Err(BadTimedSignature::TimestampExpired {
                timestamp: self.timestamp,
                value: self.value,
                max_age,
            }),
            // Timestamp is in the future or hasn't expired yet.
            Ok(_) | Err(_) => Ok(self.value),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;

    use crate::default_builder;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_sign() {
        let signer = default_builder("hello").build().into_timestamp_signer();
        let timestamp = UNIX_EPOCH + Duration::from_secs(1560181622);
        let signed = signer.sign_with_timestamp("hello world", timestamp);

        assert_eq!(signed, "hello world.D-AM9g.T7AHtE1DsJn4dzUb-oeOwpWWoX8");
        let unsigned = signer.unsign(&signed).unwrap();
        assert_eq!(unsigned.value(), "hello world");
        assert_eq!(unsigned.timestamp(), timestamp);
    }

    #[test]
    fn test_sign_expired() {
        let signer = default_builder("hello").build().into_timestamp_signer();
        let timestamp = SystemTime::now() - Duration::from_secs(60);
        let signed = signer.sign_with_timestamp("hello world", timestamp);
        let unsigned = signer.unsign(&signed).unwrap();

        assert!(unsigned
            .value_if_not_expired(Duration::from_secs(30))
            .is_err());
    }
    #[test]
    fn test_sign_not_expired() {
        let signer = default_builder("hello").build().into_timestamp_signer();
        let timestamp = SystemTime::now() - Duration::from_secs(60);
        let signed = signer.sign_with_timestamp("hello world", timestamp);
        let unsigned = signer.unsign(&signed).unwrap();

        assert!(unsigned
            .value_if_not_expired(Duration::from_secs(90))
            .is_ok());
    }

    #[bench]
    fn bench_sign(bench: &mut Bencher) {
        let signer = default_builder("hello").build().into_timestamp_signer();
        let timestamp = UNIX_EPOCH + Duration::from_secs(1560181622);

        bench.iter(|| signer.sign_with_timestamp("hello world", timestamp))
    }

    #[bench]
    fn bench_unsign(bench: &mut Bencher) {
        let signer = default_builder("hello").build().into_timestamp_signer();

        bench.iter(|| signer.unsign("hello world.D-AM9g.T7AHtE1DsJn4dzUb-oeOwpWWoX8"))
    }
}
