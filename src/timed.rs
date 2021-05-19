use std::time::{Duration, SystemTime};

use crate::algorithm::Signer as AlgorithmSigner;
use crate::base64::URLSafeBase64Encode;
use crate::error::BadTimedSignature;
use crate::signer::DefaultSigner;
use crate::timestamp;
use crate::traits::GetSigner;
use crate::{AsSigner, Separator, Signer, TimestampSigner};

pub struct TimestampSignerImpl<TSigner>(TSigner);

/// The default [`TimestampSigner`] when using [`default_builder`].
pub type DefaultTimestampSigner = TimestampSignerImpl<DefaultSigner>;

impl<TSigner> TimestampSignerImpl<TSigner>
where
    TSigner: Signer + GetSigner,
{
    pub(crate) fn with_signer(signer: TSigner) -> Self {
        Self(signer)
    }

    pub(crate) fn split<'a>(
        &'a self,
        value: &'a str,
    ) -> Result<(&'a str, &'a str), BadTimedSignature<'a>> {
        // Then we split it again, to extract the value & timestamp.
        self.0
            .separator()
            .split(value)
            .map_err(|_| BadTimedSignature::TimestampMissing { value })
    }
}

impl<TSigner> TimestampSigner for TimestampSignerImpl<TSigner>
where
    TSigner: Signer + GetSigner,
{
    fn separator(&self) -> Separator {
        self.0.separator()
    }

    /// Signs a value with an arbitrary timestamp.
    fn sign_with_timestamp<S: AsRef<str>>(&self, value: S, timestamp: SystemTime) -> String {
        let value = value.as_ref();
        let encoded_timestamp = timestamp::encode(timestamp);
        let separator = self.0.separator().0;

        // Generate the signature.
        let signature = self
            .0
            .get_signer()
            .input_chained(value.as_bytes())
            .input_chained(&[separator as u8])
            .input_chained(encoded_timestamp.as_slice())
            .sign();

        // Generate the signed output string.
        let mut output = String::with_capacity(
            value.len() + 1 + encoded_timestamp.length() + 1 + self.0.signature_output_size(),
        );

        output.push_str(value);
        output.push(separator);
        output.push_str(encoded_timestamp.as_str());
        output.push(separator);
        signature.base64_encode_str(&mut output);

        output
    }

    /// Signs a value using the current system timestamp (as provided by [`SystemTime::now`]).
    fn sign<S: AsRef<str>>(&self, value: S) -> String {
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
    fn unsign<'a>(&'a self, value: &'a str) -> Result<UnsignedValue, BadTimedSignature<'a>> {
        // The base unsigner gives us {value}{sep}{timestamp}.
        let value = self.0.unsign(value)?;
        let (value, timestamp) = self.split(value)?;
        let timestamp = timestamp::decode(timestamp)?;

        Ok(UnsignedValue { timestamp, value })
    }
}

impl<TSigner> AsSigner for TimestampSignerImpl<TSigner>
where
    TSigner: Signer,
{
    type Signer = TSigner;

    fn as_signer(&self) -> &Self::Signer {
        &self.0
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
    use crate::{default_builder, DefaultTimestampSigner, IntoTimestampSigner, TimestampSigner};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_sign() {
        let signer = default_builder("hello").build().into_timestamp_signer();
        let timestamp = UNIX_EPOCH + Duration::from_secs(1560181622);
        let signed = signer.sign_with_timestamp("hello world", timestamp);

        assert_eq!(signed, "hello world.XP57dg.uBK_KvrfABr48ZHk6IrBINjpqp8");
        let unsigned = signer.unsign(&signed).unwrap();
        assert_eq!(unsigned.value(), "hello world");
        assert_eq!(unsigned.timestamp(), timestamp);
    }

    #[test]
    fn test_default_alias() {
        let _: DefaultTimestampSigner = default_builder("hello").build().into_timestamp_signer();
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
}

#[cfg(all(test, feature = "nightly"))]
mod bench {
    use crate::*;
    use std::time::{Duration, UNIX_EPOCH};
    extern crate test;
    use test::Bencher;

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
