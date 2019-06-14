use std::ops::Deref;
use std::time::{Duration, SystemTime};

use generic_array::ArrayLength;
use serde::{de::DeserializeOwned, Serialize};
use serde_json;

use crate::algorithm::SigningAlgorithm;
use crate::base64::Base64Sized;
use crate::error::{BadSignature, BadTimedSignature, PayloadError, TimestampExpired};
use crate::timestamp;
use crate::{base64, Seperator, Signer, TimestampSigner};

pub trait Encoding {
    fn encode<'a>(&self, serialized_input: String) -> String;
    fn decode<'a>(&self, encoded_input: String) -> Result<String, PayloadError>;
}

pub struct NullEncoding;

impl Encoding for NullEncoding {
    fn encode<'a>(&self, serialized_input: String) -> String {
        serialized_input
    }

    fn decode<'a>(&self, encoded_input: String) -> Result<String, PayloadError> {
        Ok(encoded_input)
    }
}

pub struct URLSafeEncoding;

impl Encoding for URLSafeEncoding {
    fn encode<'a>(&self, serialized_input: String) -> String {
        base64::encode(&serialized_input)
    }

    fn decode<'a>(&self, encoded_input: String) -> Result<String, PayloadError> {
        // TODO: Handle decompression from... you know... python land.
        let decoded = base64::decode_str(&encoded_input)?;
        String::from_utf8(decoded)
            .map_err(|e| {
                let err = e.utf8_error();
                let bytes = e.as_bytes();
                PayloadError::Base64(base64::DecodeError::InvalidByte(
                    err.valid_up_to(),
                    bytes[err.valid_up_to()],
                ))
            })
            .map(|e| e.into())
    }
}

#[inline(always)]
fn deserialize<'a, T: DeserializeOwned, Encoding: self::Encoding>(
    value: &'a str,
    encoding: &Encoding,
) -> Result<T, BadSignature<'a>> {
    let decoded = encoding
        .decode(value.to_string())
        .map_err(|e| BadSignature::PayloadInvalid {
            value,
            error: e.into(),
        })?;
    serde_json::from_str(&decoded).map_err(|e| BadSignature::PayloadInvalid {
        value,
        error: e.into(),
    })
}

pub struct Serializer<TSigner, TEncoding> {
    signer: TSigner,
    encoding: TEncoding,
}

impl<TSigner, TEncoding> Serializer<TSigner, TEncoding>
where
    TSigner: Signer,
    TEncoding: Encoding,
{
    pub fn with_signer(signer: TSigner, encoding: TEncoding) -> Self {
        Self { signer, encoding }
    }

    pub fn sign<T: Serialize>(&self, value: &T) -> serde_json::Result<String> {
        let serialized = serde_json::to_string(value)?;
        let encoded = self.encoding.encode(serialized);
        Ok(self.signer.sign(encoded))
    }

    pub fn unsign<'a, T: DeserializeOwned>(
        &'a self,
        value: &'a str,
    ) -> Result<T, BadSignature<'a>> {
        let value = self.signer.unsign(value)?;
        deserialize(value, &self.encoding)
    }
}

pub struct TimedSerializer<TSigner, TEncoding> {
    signer: TSigner,
    encoding: TEncoding,
}

impl<TSigner, TEncoding> TimedSerializer<TSigner, TEncoding>
where
    TSigner: TimestampSigner,
    TEncoding: Encoding,
{
    pub fn with_signer(signer: TSigner, encoding: TEncoding) -> Self {
        Self { signer, encoding }
    }

    pub fn sign<T: Serialize>(&self, value: &T) -> serde_json::Result<String> {
        self.sign_with_timestamp(value, SystemTime::now())
    }

    pub fn sign_with_timestamp<T: Serialize>(
        &self,
        value: &T,
        timestamp: SystemTime,
    ) -> serde_json::Result<String> {
        let serialized = serde_json::to_string(value)?;
        let encoded = self.encoding.encode(serialized);
        Ok(self.signer.sign_with_timestamp(encoded, timestamp))
    }

    pub fn unsign<'a, T: DeserializeOwned>(
        &'a self,
        value: &'a str,
    ) -> Result<UnsignedValue<T>, BadTimedSignature<'a>> {
        let value = self.signer.unsign(value)?;
        let timestamp = value.timestamp();
        let value = value.value();
        let deserialized_value = deserialize(value, &self.encoding)?;

        Ok(UnsignedValue {
            value: deserialized_value,
            timestamp,
        })
    }
}

/// Represents a value + timestamp that has been successfully unsigned by [`TimedSerializer::unsign`].
pub struct UnsignedValue<T> {
    value: T,
    timestamp: SystemTime,
}

impl<T> UnsignedValue<T> {
    /// The value that has been [`unsigned`]. This value is safe to use and
    /// was part of a payload that has been successfully [`unsigned`].
    ///
    /// [`unsigned`]: TimedSerializer::unsign
    pub fn value(self) -> T {
        self.value
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
    /// If the value is expired, returns [`TimestampExpired`].
    pub fn value_if_not_expired(self, max_age: Duration) -> Result<T, TimestampExpired<T>> {
        match self.timestamp.elapsed() {
            Ok(duration) if duration > max_age => Err(TimestampExpired {
                timestamp: self.timestamp,
                value: self.value,
                max_age,
            }),
            // Timestamp is in the future or hasn't expired yet.
            Ok(_) | Err(_) => Ok(self.value),
        }
    }
}

impl<T> Deref for UnsignedValue<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

// TODO: Doc
pub struct UnverifiedValue<'a, T> {
    unverified_value: T,
    unverified_raw_value: &'a str,
    unverified_signature: &'a str,
}

impl<'a, T: DeserializeOwned> UnverifiedValue<'a, T> {
    pub fn from_str<Encoding: self::Encoding>(
        seperator: Seperator,
        encoding: Encoding,
        input: &'a str,
    ) -> Result<Self, BadSignature> {
        let (unverified_raw_value, unverified_signature) = seperator.split(input)?;
        let unverified_value = deserialize(unverified_raw_value, &encoding)?;

        Ok(UnverifiedValue {
            unverified_value,
            unverified_raw_value,
            unverified_signature,
        })
    }

    // XXX: Doc
    pub fn unverified_value(&self) -> &T {
        &self.unverified_value
    }

    pub fn verify<Algorithm, DerivedKeySize, SignatureEncoder>(
        self,
        signer: &crate::signer::SignerImpl<Algorithm, DerivedKeySize, SignatureEncoder>,
    ) -> Result<T, BadSignature<'a>>
    where
        Algorithm: SigningAlgorithm,
        DerivedKeySize: ArrayLength<u8>,
        SignatureEncoder: Base64Sized,
    {
        let value = self.unverified_raw_value;
        let signature = self.unverified_signature;

        if signer.verify_encoded_signature(value.as_bytes(), signature.as_bytes()) {
            Ok(self.unverified_value)
        } else {
            Err(BadSignature::SignatureMismatch { signature, value })
        }
    }
}

pub struct UnverifiedTimedValue<'a, T> {
    unverified_value: T,
    unverified_raw_value: &'a str,
    unverified_signature: &'a str,
    unverified_timestamp: SystemTime,
}

impl<'a, T: DeserializeOwned> UnverifiedTimedValue<'a, T> {
    pub fn from_str<Encoding: self::Encoding>(
        seperator: Seperator,
        encoding: Encoding,
        input: &'a str,
    ) -> Result<Self, BadTimedSignature> {
        let (unverified_raw_value, unverified_signature) = seperator.split(input)?;
        let (unverified_raw_serialized_value, unverified_timestamp) =
            seperator.split(unverified_raw_value)?;
        let unverified_timestamp = timestamp::decode(unverified_timestamp)?;
        let unverified_value = deserialize(unverified_raw_serialized_value, &encoding)?;

        Ok(UnverifiedTimedValue {
            unverified_value,
            unverified_raw_value,
            unverified_signature,
            unverified_timestamp,
        })
    }

    pub fn unverified_value(&self) -> &T {
        &self.unverified_value
    }

    pub fn unverified_timestamp(&self) -> SystemTime {
        self.unverified_timestamp
    }

    pub fn verify<TSigner: TimestampSigner>(
        self,
        timestamp_signer: &TSigner,
    ) -> Result<UnsignedValue<T>, BadTimedSignature<'a>> {
        let value = self.unverified_raw_value;
        let signature = self.unverified_signature;

        if timestamp_signer
            .as_signer()
            .verify_encoded_signature(value.as_bytes(), signature.as_bytes())
        {
            Ok(UnsignedValue {
                value: self.unverified_value,
                timestamp: self.unverified_timestamp,
            })
        } else {
            Err(BadTimedSignature::SignatureMismatch { signature, value })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::default_builder;
    #[test]

    fn test_null_encoding() {
        let s = "hello world".to_owned();
        let encoding = NullEncoding;
        assert_eq!(encoding.encode(s.clone()), s);
        assert_eq!(encoding.decode(s.clone()).unwrap(), s);
    }

    #[test]
    fn test_url_safe_encoding() {
        let s = "hello world".to_owned();
        let encoded = "aGVsbG8gd29ybGQ".to_owned();
        let encoding = URLSafeEncoding;
        assert_eq!(encoding.encode(s.clone()), encoded);
        assert_eq!(encoding.decode(encoded).unwrap(), s);
    }

    #[test]
    fn test_sign_null_encoding() {
        let signer = default_builder("hello world").build();
        let serializer = Serializer::with_signer(signer, NullEncoding);
        let signed = "[1,2,3].bq_ST5hV4J35lKdovyr_ng-ZIxU";
        assert_eq!(serializer.sign(&vec![1, 2, 3]).unwrap(), signed);
        assert_eq!(serializer.unsign::<Vec<u8>>(signed).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_unsign_unverified_good_signature() {
        let signer = default_builder("hello world").build();
        let signed = "[1,2,3].bq_ST5hV4J35lKdovyr_ng-ZIxU";
        let unverified_value: UnverifiedValue<Vec<u8>> =
            UnverifiedValue::from_str(signer.seperator, NullEncoding, signed).unwrap();
        let expected = vec![1, 2, 3];
        assert_eq!(unverified_value.unverified_value(), &expected);
        assert_eq!(unverified_value.verify(&signer).unwrap(), expected);
    }

    #[test]
    fn test_unsign_unverified_bad_signature() {
        let signer = default_builder("not the right key lol").build();
        let signed = "[1,2,3].bq_ST5hV4J35lKdovyr_ng-ZIxU";
        let unverified_value: UnverifiedValue<Vec<u8>> =
            UnverifiedValue::from_str(signer.seperator, NullEncoding, signed).unwrap();
        let expected = vec![1, 2, 3];
        assert_eq!(unverified_value.unverified_value(), &expected);
        assert!(unverified_value.verify(&signer).is_err());
    }

    #[test]
    fn test_sign_url_safe_encoding() {
        let signer = default_builder("hello world").build();
        let serializer = Serializer::with_signer(signer, URLSafeEncoding);
        let signed = "WzEsMiwzXQ.ohh92zNcvFVoWHrPf5uumLp6mbQ";
        assert_eq!(serializer.sign(&vec![1, 2, 3]).unwrap(), signed);
        assert_eq!(serializer.unsign::<Vec<u8>>(signed).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_timed_sign_null_encoding() {
        let signer = default_builder("hello world")
            .build()
            .into_timestamp_signer();
        let serializer = TimedSerializer::with_signer(signer, NullEncoding);
        let timestamp = UNIX_EPOCH + Duration::from_secs(1560181622);
        let signed = "[1,2,3].D-AM9g.nHmuOEE3v5DuwHEW9noSBOvExO0";
        assert_eq!(
            serializer
                .sign_with_timestamp(&vec![1, 2, 3], timestamp)
                .unwrap(),
            signed
        );
        let unsigned = serializer.unsign::<Vec<u8>>(signed).unwrap();
        assert_eq!(unsigned.timestamp(), timestamp);
        assert_eq!(unsigned.value(), vec![1, 2, 3]);
    }

    #[test]
    fn test_unverified_timed_good_signature() {
        let signer = default_builder("hello world")
            .build()
            .into_timestamp_signer();
        let timestamp = UNIX_EPOCH + Duration::from_secs(1560181622);
        let signed = "[1,2,3].D-AM9g.nHmuOEE3v5DuwHEW9noSBOvExO0";
        let unverified_value: UnverifiedTimedValue<Vec<u8>> =
            UnverifiedTimedValue::from_str(signer.seperator(), NullEncoding, signed).unwrap();
        let expected = vec![1, 2, 3];
        assert_eq!(unverified_value.unverified_timestamp(), timestamp);
        assert_eq!(unverified_value.unverified_value(), &expected);
        assert_eq!(unverified_value.verify(&signer).unwrap().value(), expected);
    }

    // TODO: Test `value_if_not_expired` & co...
}
