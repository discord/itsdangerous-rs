use serde::{de::DeserializeOwned, Serialize};

use crate::serializer_traits::UnsignToString;
use crate::{BadSignature, Serializer};

/// The [`MultiSerializer`] provides the ability to sign values with a
/// given serializer, but also try a series of fallback serializers.
/// This is useful if you are rotating keys, and want to sign things
/// using a new key, but allow an old serializer to unsign values.
///
/// # Exmaple
/// ```rust
/// use itsdangerous::*;
///
/// let primary = serializer_with_signer(default_builder("new key").build(), URLSafeEncoding);
/// let fallback = serializer_with_signer(default_builder("old key").build(), URLSafeEncoding);
///
/// let signed_with_new_key = primary.sign(&"Signed with new key".to_owned()).unwrap();
/// let signed_with_old_key = fallback.sign(&"Signed with old key".to_owned()).unwrap();
///
/// let multi = MultiSerializer::new(primary).add_fallback(fallback);
///
/// assert_eq!(multi.unsign::<String>(&signed_with_new_key).unwrap(), "Signed with new key");
/// assert_eq!(multi.unsign::<String>(&signed_with_old_key).unwrap(), "Signed with old key");
/// ```
pub struct MultiSerializer<PrimarySerializer> {
    primary_serializer: PrimarySerializer,
    fallback_serializers: Vec<Box<dyn UnsignToString>>,
}

impl<PrimarySerializer> MultiSerializer<PrimarySerializer>
where
    PrimarySerializer: Serializer,
{
    /// Constructs a new [`MultiSerializer`] with a given [`Serializer`] as the primary
    /// serializer. The primary serializer is the one that will be used to sign values,
    /// and the first serializer that will be attempted while trying to unsign.
    ///
    /// # Remarks
    /// If the primary serializer is used to unsign a value, no dynamic dispatch takes
    /// place. That is to say, the [`MultiSerializer`] is its fastest when only the
    /// primary serializer is required to unsign a value, and when signing a value,
    /// it is a zero-cost abstraction.
    pub fn new(primary_serializer: PrimarySerializer) -> Self {
        Self {
            primary_serializer,
            fallback_serializers: Vec::new(),
        }
    }

    /// Adds a [`Serializer`] to as a fallback, that will be attempted to be used to
    /// unsign a value if the primary serializer fails to unsign a value.
    ///
    /// # Remarks
    /// Fallback serializers are attempted in the order they are added. For optimal
    /// performance when using fallbacks, add them in the order they will probably
    /// be used. Meaning, if you have a 2 fallbacks, consider adding the one you
    /// expect to be sucecessful before the other.
    pub fn add_fallback<FallbackSerializer>(
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

        let multi = MultiSerializer::new(primary).add_fallback(secondary);

        assert_eq!(multi.sign(&"hello".to_owned()).unwrap(), a);
        assert_eq!(multi.unsign::<String>(&a).unwrap(), "hello".to_owned());
        assert_eq!(multi.unsign::<String>(&b).unwrap(), "world".to_owned());
        assert!(multi.unsign::<String>(&c).is_err());
    }
}
