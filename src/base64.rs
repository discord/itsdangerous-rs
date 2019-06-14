use std::ops::{Add, Div, Mul, Rem};

use hmac::digest::generic_array::typenum::*;

use base64;
pub use base64::DecodeError;

use hmac::digest::generic_array::{ArrayLength, GenericArray};

static BASE64_ALPHABET: &'static str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=";

/// A trait that allows a type to be safely encoded as a url-safe
/// basea64 string.
pub trait URLSafeBase64Encode: Sized {
    #[cfg(test)]
    fn base64_encode(self) -> String {
        let mut target = String::new();
        self.base64_encode_str(&mut target);
        target
    }

    fn base64_encode_str(self, target: &mut String);
}

/// Encodes a string as url safe base64.
#[inline(always)]
pub(crate) fn encode<T>(input: &T) -> String
where
    T: ?Sized + AsRef<[u8]>,
{
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

/// Encodes a string as url safe base64.
#[inline(always)]
pub(crate) fn encode_slice<T>(input: &T, target: &mut [u8]) -> usize
where
    T: ?Sized + AsRef<[u8]>,
{
    base64::encode_config_slice(input, base64::URL_SAFE_NO_PAD, target)
}

/// Encodes a string as url safe base64.
#[inline(always)]
pub(crate) fn encode_str<T>(input: &T, target: &mut String)
where
    T: ?Sized + AsRef<[u8]>,
{
    base64::encode_config_buf(input, base64::URL_SAFE_NO_PAD, target)
}

pub(crate) struct DecodeResult<N: ArrayLength<u8>> {
    array: GenericArray<u8, N>,
    length: usize,
}

impl<N: ArrayLength<u8>> DecodeResult<N> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.array[..self.length]
    }

    pub(crate) fn into_exact_inner(self) -> Result<GenericArray<u8, N>, DecodeError> {
        if self.array.len() != self.length {
            Err(DecodeError::InvalidLength)
        } else {
            Ok(self.array)
        }
    }
}

/// Decodes a base64 encoded string from `URLSafeBase64Encode` to a sized GenericArray.
#[inline(always)]
pub(crate) fn decode<N, T>(input: &T) -> Result<DecodeResult<N>, DecodeError>
where
    N: ArrayLength<u8>,
    T: ?Sized + AsRef<[u8]>,
{
    let mut array = GenericArray::default();
    let length = base64::decode_config_slice(input, base64::URL_SAFE_NO_PAD, &mut array)?;
    Ok(DecodeResult { array, length })
}

/// Decodes a base64 encoded string from `URLSafeBase64Encode` to a sized GenericArray.
#[inline(always)]
pub(crate) fn decode_str<T>(input: &T) -> Result<Vec<u8>, DecodeError>
where
    T: ?Sized + AsRef<[u8]>,
{
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
}

/// Returns whether or not a given character is in the base64 alphabet.
pub(crate) fn in_alphabet(c: char) -> bool {
    BASE64_ALPHABET.contains(c)
}

/// A trait that is implemented by `Base64SizedEncoder` that provides facilities
/// for encoding a GenericArray as base64. All sizing is computed during compile
/// time.
pub trait Base64Sized {
    type InputSize: ArrayLength<u8>;
    type OutputSize: ArrayLength<u8>;

    fn encode(input: GenericArray<u8, Self::InputSize>) -> GenericArray<u8, Self::OutputSize>;
    fn output_size() -> usize;
}

pub struct Base64SizedEncoder<N>(N);

/// Implementation of the `Base64Sized` trait. This does the actual computation.
///
/// A simple example is as follows:
/// ```rust
/// use itsdangerous::base64::{Base64Sized, Base64SizedEncoder};
/// use hmac::digest::generic_array::*;
///
/// let arr = arr![u8; 1, 2, 3];
/// let result = Base64SizedEncoder::encode(arr);
/// ```
impl<N> Base64Sized for Base64SizedEncoder<N>
where
    // -----------------------------------------------------------------------
    // The algorithm for computing the size of a non-padded base-64 array is:
    //   ((N / 3) * 4) + (N % 3) + Min((N % 3), 1)
    // The code below does that computation using the `typenum` type system.
    // The computation must be broken into partial type assertions for each
    // operation that will be performed.
    //
    // Breaking down the formula above involves breaking down each binary
    // operation (e.g. A [op] B, or A + B), and then building upon them.
    //
    // For example: (N / 3) * 4 is broken down into two operations, and
    // composes the computed type as follows, with trait assertions for
    // each incremental operation, eventually building up to the result (R)
    //  1: N / 3 = X   (N: Div<U3>)
    //  2: X * 4       (Quot<N, U3>: Mul<U4>)
    //  R: Prod<Quot<N, U3>, U4>>
    // -----------------------------------------------------------------------
    // N is a type that represents an Unsigned number and an Array Length
    N: Unsigned + ArrayLength<u8>,
    // (N % 3)
    N: Rem<U3>,
    // (N / 3)
    N: Div<U3>,
    // (N / 3) * 4
    Quot<N, U3>: Mul<U4>,
    // Min((N % 3), 1)
    Mod<N, U3>: Min<U1>,
    // (N % 3) + Min(N % 3, 1)
    Mod<N, U3>: Add<Minimum<Mod<N, U3>, U1>>,
    // ((N / 3) * 4) + (N % 3) + Min((N % 3), 1)
    Prod<Quot<N, U3>, U4>: Add<Sum<Mod<N, U3>, Minimum<Mod<N, U3>, U1>>>,
    // Finally evaluate the formula in parts above and enforce the trait bounds.
    Sum<Prod<Quot<N, U3>, U4>, Sum<Mod<N, U3>, Minimum<Mod<N, U3>, U1>>>:
        Unsigned + ArrayLength<u8>,
{
    type InputSize = N;
    // This is a copy-pasta of the final `where` clause type assertion.
    type OutputSize = Sum<Prod<Quot<N, U3>, U4>, Sum<Mod<N, U3>, Minimum<Mod<N, U3>, U1>>>;

    fn encode(input: GenericArray<u8, Self::InputSize>) -> GenericArray<u8, Self::OutputSize> {
        let mut output = GenericArray::default();
        let size = encode_slice(input.as_slice(), output.as_mut_slice());
        debug_assert_eq!(size, Self::OutputSize::to_usize());
        output
    }

    fn output_size() -> usize {
        Self::OutputSize::to_usize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_sized_encoder() {
        fn gen_string<N: ArrayLength<u8>>() -> GenericArray<u8, N> {
            let mut output: GenericArray<_, _> = Default::default();
            for c in output.as_mut_slice() {
                *c = 'a' as u8;
            }
            output
        }

        // Sanity check length calculation.
        assert_eq!(Base64SizedEncoder::<U1>::output_size(), 2);
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U1>()).as_slice(),
            &[89, 81]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U2>()).as_slice(),
            &[89, 87, 69]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U3>()).as_slice(),
            &[89, 87, 70, 104]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U4>()).as_slice(),
            &[89, 87, 70, 104, 89, 81]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U5>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 69]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U6>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U7>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 81]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U8>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 69]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U9>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U10>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 81]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U11>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 69]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U12>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U13>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 81]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U14>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 69]
        );
        assert_eq!(
            Base64SizedEncoder::encode(gen_string::<U15>()).as_slice(),
            &[89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104, 89, 87, 70, 104]
        );
    }
}
