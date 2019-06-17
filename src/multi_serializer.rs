use serde::{de::DeserializeOwned, Serialize};

use crate::serializer_traits::UnsignToString;
use crate::{BadSignature, Serializer};

pub struct MultiSerializer<PrimarySerializer> {
    primary_serializer: PrimarySerializer,
    fallback_serializers: Vec<Box<dyn UnsignToString>>,
}

impl<PrimarySerializer> MultiSerializer<PrimarySerializer>
where
    PrimarySerializer: Serializer,
{
    pub fn new(primary_serializer: PrimarySerializer) -> Self {
        Self {
            primary_serializer,
            fallback_serializers: Vec::new(),
        }
    }

    pub fn add_fallback_serializer<FallbackSerializer>(
        mut self,
        fallback_serializer: FallbackSerializer,
    ) -> Self
    where
        FallbackSerializer: UnsignToString + 'static,
    {
        self.fallback_serializers
            .push(Box::new(fallback_serializer));

        self
    }
}

impl<PrimarySerializer> Serializer for MultiSerializer<PrimarySerializer>
where
    PrimarySerializer: Serializer,
{
    fn sign<T: Serialize>(&self, value: &T) -> serde_json::Result<String> {
        self.primary_serializer.sign(value)
    }

    fn unsign<'a, T: DeserializeOwned>(&'a self, value: &'a str) -> Result<T, BadSignature<'a>> {
        let primary_serializer_error = match self.primary_serializer.unsign(value) {
            Ok(unsigned) => return Ok(unsigned),
            Err(err) => err,
        };

        for serializer in &self.fallback_serializers {
            if let Ok(unsigned) = serializer.unsign_to_string(value) {
                return serde_json::from_str(&unsigned).map_err(|e| BadSignature::PayloadInvalid {
                    value,
                    error: e.into(),
                });
            }
        }

        Err(primary_serializer_error)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_multi_serializer() {
        let primary = serializer_with_signer(default_builder("primary").build(), URLSafeEncoding);
        let secondary = serializer_with_signer(default_builder("secondary").build(), NullEncoding);
        let irrelevant =
            serializer_with_signer(default_builder("irrelevant").build(), NullEncoding);

        let a = primary.sign(&"hello".to_owned()).unwrap();
        let b = secondary.sign(&"world".to_owned()).unwrap();
        let c = irrelevant.sign(&"danger!".to_owned()).unwrap();

        let multi = MultiSerializer::new(primary).add_fallback_serializer(secondary);

        assert_eq!(multi.sign(&"hello".to_owned()).unwrap(), a);
        assert_eq!(multi.unsign::<String>(&a).unwrap(), "hello".to_owned());
        assert_eq!(multi.unsign::<String>(&b).unwrap(), "world".to_owned());
        assert!(multi.unsign::<String>(&c).is_err());
    }
}
