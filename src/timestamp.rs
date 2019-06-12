use std::mem;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use generic_array::{self, ArrayLength, GenericArray};
use typenum::{Unsigned, U8};

use crate::base64::{self, Base64Sized, Base64SizedEncoder};
use crate::error::BadTimedSignature;

const LEGACY_EPOCH: u64 = 1293840000;

pub(crate) struct EncodedTimestamp<N: ArrayLength<u8>> {
    array: GenericArray<u8, N>,
    length: usize,
}

impl<N: ArrayLength<u8>> EncodedTimestamp<N> {
    #[inline(always)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.array[..self.length]
    }

    #[inline(always)]
    pub(crate) fn length(&self) -> usize {
        self.length
    }

    #[inline(always)]
    pub(crate) fn as_str(&self) -> &str {
        // This is safe, because we know that an encoded timestamp's bytes
        // are within the url-safe base64 alphabet, which is plain ascii,
        // and totally fine to coerce to utf8.
        unsafe { std::str::from_utf8_unchecked(self.as_slice()) }
    }
}

type TimestampEncoder = Base64SizedEncoder<U8>;

#[inline(always)]
pub(crate) fn encode(
    timestamp: SystemTime,
) -> EncodedTimestamp<<TimestampEncoder as Base64Sized>::OutputSize> {
    type InputSize = <TimestampEncoder as Base64Sized>::InputSize;
    // This is compatible with itsdangerous 0.x, which is what we're using in prod right now.
    let epoch_delta: u64 = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() - LEGACY_EPOCH;

    // Fastest transform + strip + encode in the west.
    // - The nice thing is that this is compile time checked to be a sane transformation, e.g.,
    //   if TimestampEncoder was initialized using say a <U9>, the code just wouldn't compile!
    let timestamp_bytes: [u8; InputSize::USIZE] = unsafe { mem::transmute(epoch_delta.to_be()) };

    // We need to strip the leading zero bytes, to do that, we take the leading
    // zeroes, and count em.
    let zero_index = timestamp_bytes
        .into_iter()
        .take_while(|b| **b == 0u8)
        .count();

    // Finally, we can do the encoding.
    let mut array = GenericArray::default();
    let length = base64::encode_slice(&timestamp_bytes[zero_index..], array.as_mut_slice());
    EncodedTimestamp { array, length }
}

#[inline(always)]
pub(crate) fn decode(timestamp: &str) -> Result<SystemTime, BadTimedSignature> {
    type InputSize = <TimestampEncoder as Base64Sized>::InputSize;

    // Decode the base-64 encoded timestamp to bytes.
    let timestamp_bytes = base64::decode::<InputSize, _>(timestamp)
        .map_err(|_| BadTimedSignature::TimestampInvalid { timestamp })?;

    let timestamp_bytes = timestamp_bytes.as_slice();

    // We need to then re-pad the bytes so we can then transmute it into an array.
    let mut input_array: GenericArray<u8, InputSize> = GenericArray::default();
    input_array[InputSize::USIZE - timestamp_bytes.len()..].copy_from_slice(timestamp_bytes);

    // Finally, take those bytes and re-interpret them
    let timestamp_secs: u64 = unsafe { generic_array::transmute(input_array) };
    let timestamp_duration = Duration::from_secs(timestamp_secs.to_be() + LEGACY_EPOCH);

    // Convert from timestamp to a SystemTime - handle the overflow by returning TimestampInvalid.
    UNIX_EPOCH
        .checked_add(timestamp_duration)
        .ok_or_else(|| BadTimedSignature::TimestampInvalid { timestamp })
}
