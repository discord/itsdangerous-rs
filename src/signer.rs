use std::borrow::Cow;
use std::marker::PhantomData;

use generic_array::{ArrayLength, GenericArray};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use typenum::Unsigned;

use crate::algorithm::{self, Signature};
use crate::base64::{self, Base64Sized, Base64SizedEncoder, URLSafeBase64Encode};
use crate::key_derivation;
use crate::{BadSignature, Seperator, TimestampSigner};

static DEFAULT_SALT: Cow<'static, str> = Cow::Borrowed("itsdangerous.Signer");

pub struct SignerBuilder<Digest, Algorithm, KeyDerivation> {
    secret_key: Cow<'static, str>,
    salt: Cow<'static, str>,
    seperator: Seperator,
    _phantom: PhantomData<(Digest, Algorithm, KeyDerivation)>,
}

/// Constructs a default signer builder, using the [`sha1`] digest, [`hmac`],
/// and the [`django concat`] key derivation.
///
/// [`django concat`]: crate::key_derivation::DjangoConcat
pub fn default_builder<S: Into<Cow<'static, str>>>(
    secret_key: S,
) -> SignerBuilder<sha1::Sha1, algorithm::HMACAlgorithm<sha1::Sha1>, key_derivation::DjangoConcat> {
    SignerBuilder::new(secret_key)
}

impl<Digest, Algorithm, KeyDerivation> SignerBuilder<Digest, Algorithm, KeyDerivation>
where
    Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    Digest::BlockSize: ArrayLength<u8> + Clone,
    Digest::OutputSize: ArrayLength<u8>,
    Algorithm: algorithm::SigningAlgorithm,
    Algorithm::OutputSize: ArrayLength<u8>,
    KeyDerivation: key_derivation::DeriveKey,
{
    /// Constructs a new signer builder with a given secret key.
    pub fn new<S: Into<Cow<'static, str>>>(secret_key: S) -> Self {
        Self {
            secret_key: secret_key.into(),
            salt: DEFAULT_SALT.clone(),
            seperator: Default::default(),
            _phantom: PhantomData,
        }
    }

    /// Uses a specific salt with the signer. If no salt is defined, will
    /// default to `DEFAULT_SALT`.
    pub fn with_salt<S: Into<Cow<'static, str>>>(mut self, salt: S) -> Self {
        self.salt = salt.into();
        self
    }

    /// Uses a specific seperator with the signer. If no seperator is
    /// defined, will default to '.'
    pub fn with_seperator(mut self, seperator: Seperator) -> Self {
        self.seperator = seperator;
        self
    }

    /// Builds a Signer using the configuration specified in this builder.
    pub fn build(
        self,
    ) -> Signer<Algorithm, Digest::OutputSize, Base64SizedEncoder<Algorithm::OutputSize>> {
        let derived_key = KeyDerivation::derive_key::<Digest>(&self.secret_key, &self.salt);

        Signer {
            derived_key,
            seperator: self.seperator,
            _phantom: PhantomData,
        }
    }
}

/// This struct can sign and unsign bytes, validating the signature provided.
///
/// A salt can be used to namespace the hash, so that a signed string is only
/// valid for a given namespace. Leaving this at the default value or re-using a salt value
/// across different parts of your application where the same signed value in one part can
/// mean something different in another part is a security risk.
///
/// # Basic Usage
/// ```rust
/// use std::time::Duration;
/// use itsdangerous::default_builder;
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
pub struct Signer<Algorithm, DerivedKeySize, SignatureEncoder>
where
    DerivedKeySize: ArrayLength<u8>,
{
    derived_key: GenericArray<u8, DerivedKeySize>,
    pub(crate) seperator: Seperator,
    _phantom: PhantomData<(Algorithm, SignatureEncoder)>,
}

impl<Algorithm, DerivedKeySize, SignatureEncoder>
    Signer<Algorithm, DerivedKeySize, SignatureEncoder>
where
    Algorithm: algorithm::SigningAlgorithm,
    DerivedKeySize: ArrayLength<u8>,
    SignatureEncoder: Base64Sized,
{
    /// Signs the given string.
    #[inline(always)]
    pub fn sign<S: AsRef<str>>(&self, value: S) -> String {
        let value = value.as_ref();
        // Pre-allocate a string with the correct size (for maximum speeds.)
        // This (albeit a bit artisnal approach) is much faster than using `format!(...)`.
        let mut output =
            String::with_capacity(value.len() + 1 + SignatureEncoder::OutputSize::USIZE);

        output.push_str(value);
        output.push(self.seperator().0);
        self.get_signature(value.as_bytes())
            .base64_encode_str(&mut output);

        output
    }

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
    #[inline(always)]
    pub fn unsign<'a>(&'a self, value: &'a str) -> Result<&'a str, BadSignature<'a>> {
        let (value, signature) = self.seperator.split(&value)?;
        if self.verify_encoded_signature(value.as_bytes(), signature.as_bytes()) {
            Ok(value)
        } else {
            Err(BadSignature::SignatureMismatch { signature, value })
        }
    }

    /// Converts this [`Signer`] into a [`TimestampSigner`], giving it the ability
    /// to do signing with timestamps!
    pub fn into_timestamp_signer(
        self,
    ) -> TimestampSigner<Algorithm, DerivedKeySize, SignatureEncoder> {
        TimestampSigner::with_signer(self)
    }

    /// Gets the signature for a given value.
    #[inline(always)]
    pub(crate) fn get_signature(&self, value: &[u8]) -> Signature<Algorithm::OutputSize> {
        Algorithm::get_signature(self.derived_key.as_slice(), value)
    }

    /// Gets a signer that can produce a signature for a given value.
    #[inline(always)]
    pub(crate) fn get_signer(&self) -> Algorithm::Signer {
        Algorithm::get_signer(self.derived_key.as_slice())
    }

    /// Gets the seperator that this signer is using.
    #[inline(always)]
    pub(crate) fn seperator(&self) -> Seperator {
        self.seperator
    }

    /// Given a base64-encoded signature, attempt to decode it and convert it
    /// to a Signature.
    ///
    /// A signature is considered base64 encoded if it was encoded using
    /// `URLSafeBase64Encode::base64_encode`.
    #[inline(always)]
    fn decode_signature(
        &self,
        encoded_signature: &[u8],
    ) -> Result<Signature<Algorithm::OutputSize>, base64::DecodeError> {
        Ok(base64::decode(encoded_signature)?
            .into_exact_inner()?
            .into())
    }

    /// Given a base-64 encoded signature, attempt to verify whether or not
    /// it is valid for the given `value`.
    #[inline(always)]
    pub(crate) fn verify_encoded_signature(&self, value: &[u8], encoded_signature: &[u8]) -> bool {
        match self.decode_signature(encoded_signature) {
            Ok(sig) => self.verify_signature(value, sig),
            Err(_) => false,
        }
    }

    /// Given a signature, attempt to verify whether or not it is valid
    /// for the given `value`.
    #[inline(always)]
    fn verify_signature(
        &self,
        value: &[u8],
        expected_signature: Signature<Algorithm::OutputSize>,
    ) -> bool {
        let computed_signature = self.get_signature(value);
        expected_signature == computed_signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // extern crate test;
    // use test::Bencher;

    #[test]
    fn test_signature_basic() {
        let signer = default_builder("hello").build();
        let signature = signer.sign("this is a test");
        // This is a compatibility test against python.
        assert_eq!(signature, "this is a test.hgGT0Zoara4L13FX3_xm-xmfa_0");
        assert_eq!(
            signer
                .unsign("this is a test.hgGT0Zoara4L13FX3_xm-xmfa_0")
                .unwrap(),
            "this is a test"
        );
    }

    #[test]
    fn test_non_default_seperator() {
        let signer = default_builder("hello")
            .with_seperator(Seperator::new('!').unwrap())
            .build();
        let signature = signer.sign("this is a test");
        assert_eq!(signature, "this is a test!hgGT0Zoara4L13FX3_xm-xmfa_0");
    }

    #[test]
    fn test_default_seperator() {
        assert!(!base64::in_alphabet(Seperator::default().0));
    }

    #[test]
    fn test_seperator_rejects_invalid_char() {
        assert!(Seperator::new('a').is_err());
    }

    #[test]
    fn test_unsign_edge_cases() {
        let signer = default_builder("hello").build();

        assert!(signer.unsign("").is_err());
        assert!(signer.unsign("fish").is_err());
        assert!(signer.unsign(".").is_err());
        assert!(signer.unsign("w.").is_err());
        assert!(signer.unsign(".w").is_err());
    }

    // #[bench]
    // fn bench_unsign(bench: &mut Bencher) {
    //     let signer = default_builder("hello").build();
    //     bench.iter(|| signer.unsign("this is a test.hgGT0Zoara4L13FX3_xm-xmfa_0"))
    // }

    // #[bench]
    // fn bench_sign(bench: &mut Bencher) {
    //     let signer = default_builder("hello").build();
    //     bench.iter(|| signer.sign("this is a test"))
    // }
}
