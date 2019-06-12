use std::marker::PhantomData;

use generic_array::{arr, typenum, ArrayLength, GenericArray};
use hmac::crypto_mac::{Mac, MacResult};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use hmac::Hmac;
use typenum::Unsigned;

use crate::base64::{self, URLSafeBase64Encode};

/// A trait which implements signature generation functionality.
pub trait SigningAlgorithm {
    type OutputSize: ArrayLength<u8> + Unsigned;
    type Signer: Signer<OutputSize = Self::OutputSize>;

    /// Returns a signer that can be used to build a signature for a given key + values.
    fn get_signer(key: &[u8]) -> Self::Signer {
        Self::Signer::new(key)
    }

    /// Returns the signature for a given key + value.
    fn get_signature(key: &[u8], value: &[u8]) -> Signature<Self::OutputSize> {
        Self::get_signer(key).input_chained(value).sign()
    }
}

/// A trait which implements a Signer, which you can append
/// inputs to, and then generate a final signature with.
pub trait Signer: Sized {
    type OutputSize: ArrayLength<u8>;

    fn new(key: &[u8]) -> Self;

    fn input(&mut self, value: &[u8]);

    fn sign(self) -> Signature<Self::OutputSize>;

    fn input_chained(mut self, value: &[u8]) -> Self {
        self.input(value);
        self
    }
}

/// Provides an algorithm that does not perform any signing and
/// returns an empty signature.
pub struct NoneAlgorithm;

impl SigningAlgorithm for NoneAlgorithm {
    type OutputSize = typenum::U0;
    type Signer = NoneSigner;
}

#[doc(hidden)]
pub struct NoneSigner;
impl Signer for NoneSigner {
    type OutputSize = typenum::U0;

    fn new(_key: &[u8]) -> Self {
        Self {}
    }

    #[inline(always)]
    fn input(&mut self, _value: &[u8]) {
        // Does nothing.
    }

    #[inline(always)]
    fn sign(self) -> Signature<Self::OutputSize> {
        MacResult::new(arr![u8; ]).into()
    }
}

/// Provides an algorithm that does signature generation using HMAC's,
/// given a specific Digest.
pub struct HMACAlgorithm<Digest>(PhantomData<Digest>);

impl<Digest> SigningAlgorithm for HMACAlgorithm<Digest>
where
    Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    Digest::BlockSize: ArrayLength<u8> + Clone,
    Digest::OutputSize: ArrayLength<u8>,
{
    type OutputSize = Digest::OutputSize;
    type Signer = HMACSigner<Digest>;
}

#[doc(hidden)]
pub struct HMACSigner<Digest>(Hmac<Digest>)
where
    Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    Digest::BlockSize: ArrayLength<u8> + Clone,
    Digest::OutputSize: ArrayLength<u8>;

impl<Digest> Signer for HMACSigner<Digest>
where
    Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    Digest::BlockSize: ArrayLength<u8> + Clone,
    Digest::OutputSize: ArrayLength<u8>,
{
    type OutputSize = Digest::OutputSize;

    fn new(key: &[u8]) -> Self {
        let mac: Hmac<Digest> = Hmac::new_varkey(key).unwrap();
        Self(mac)
    }

    #[inline(always)]
    fn input(&mut self, value: &[u8]) {
        self.0.input(value)
    }

    #[inline(always)]
    fn sign(self) -> Signature<Self::OutputSize> {
        self.0.result().into()
    }
}

/// Represents a computed signature.
///
/// Two signatures of the same type can be compared safely using Eq/PartialEq,
/// thanks to the underlying constant time comparison provided by MacResult.
#[derive(Eq)]
pub struct Signature<N: ArrayLength<u8>>(MacResult<N>);

impl<N: ArrayLength<u8>> Signature<N> {
    #[inline(always)]
    fn code(self) -> GenericArray<u8, N> {
        self.0.code()
    }
}

impl<N: ArrayLength<u8>> URLSafeBase64Encode for Signature<N> {
    fn base64_encode_str(self, target: &mut String) {
        base64::encode_str(self.code().as_slice(), target)
    }
}

impl<N: ArrayLength<u8>> PartialEq for Signature<N> {
    fn eq(&self, x: &Signature<N>) -> bool {
        self.0 == x.0
    }
}

impl<N: ArrayLength<u8>> From<MacResult<N>> for Signature<N> {
    fn from(mac: MacResult<N>) -> Self {
        Self(mac)
    }
}

impl<N: ArrayLength<u8>> From<GenericArray<u8, N>> for Signature<N> {
    fn from(code: GenericArray<u8, N>) -> Self {
        Self(MacResult::new(code))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sha1::Sha1;
    #[test]
    fn test_hmac_algorithm() {
        type Algorithm = HMACAlgorithm<Sha1>;
        let signature = Algorithm::get_signature(b"foo", b"bar");
        let signature2 = Algorithm::get_signer(b"foo").input_chained(b"bar").sign();

        assert!(signature == signature2);
        // This is tested against Python's `HMACAlgorithm` implementation.
        assert_eq!(signature.base64_encode(), "RrTsWGEXFU2s1J1mTl1j_ciO-1E");
    }

    #[test]
    fn test_none_algorithm() {
        type Algorithm = NoneAlgorithm;
        let signature = Algorithm::get_signature(b"foo", b"bar");
        let signature2 = Algorithm::get_signer(b"foo").input_chained(b"bar").sign();

        assert!(signature == signature2);
        assert_eq!(signature.base64_encode(), "");
    }
}
