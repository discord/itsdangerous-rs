// TODO: Doc these traits.
use std::time::SystemTime;

use serde::{de::DeserializeOwned, Serialize};

use crate::{BadSignature, BadTimedSignature, PayloadError, UnsignedTimedSerializerValue};

pub trait Encoding {
    fn encode<'a>(&self, serialized_input: String) -> String;
    fn decode<'a>(&self, encoded_input: String) -> Result<String, PayloadError>;
}

pub trait Serializer {
    fn sign<T: Serialize>(&self, value: &T) -> serde_json::Result<String>;
    fn unsign<'a, T: DeserializeOwned>(&'a self, value: &'a str) -> Result<T, BadSignature<'a>>;
}

pub trait TimedSerializer {
    fn sign<T: Serialize>(&self, value: &T) -> serde_json::Result<String>;
    fn sign_with_timestamp<T: Serialize>(
        &self,
        value: &T,
        timestamp: SystemTime,
    ) -> serde_json::Result<String>;
    fn unsign<'a, T: DeserializeOwned>(
        &'a self,
        value: &'a str,
    ) -> Result<UnsignedTimedSerializerValue<T>, BadTimedSignature<'a>>;
}

pub trait UnsignToString {
    fn unsign_to_string<'a>(&'a self, value: &'a str) -> Result<String, BadSignature<'a>>;
}
