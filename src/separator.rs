use crate::base64;
use crate::error::{InvalidSeparator, SeparatorNotFound};

/// A separator character that can be used in [`crate::SignerBuilder::with_separator`].
///
/// This is used to join the various parts of the signed payload.
///
/// # Basic Usage
/// ```rust
/// use itsdangerous::{default_builder, Separator};
///
/// // Creates a separator using a given character.
/// let separator = Separator::new('!').expect("Invalid separator :(");
/// // Use that separator in the builder.
/// let signer = default_builder("hello")
///     .with_separator(separator)
///     .build();
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Separator(pub(crate) char);

impl Separator {
    /// Creates a new separator, checking to make sure it is valid.
    ///
    /// A valid separator is a character that is not in the
    /// base-64 url-safe alphabet.
    pub fn new(separator: char) -> Result<Self, InvalidSeparator> {
        if base64::in_alphabet(separator) {
            Err(InvalidSeparator(separator))
        } else {
            Ok(Self(separator))
        }
    }

    #[inline(always)]
    pub fn split<'a>(&self, value: &'a str) -> Result<(&'a str, &'a str), SeparatorNotFound> {
        let mut iterator = value.rsplitn(2, self.0);
        let second = iterator.next().unwrap();
        let first = match iterator.next() {
            None => return Err(SeparatorNotFound { separator: *self }),
            Some(val) => val,
        };
        Ok((first, second))
    }

    pub const fn default() -> Self {
        Self('.')
    }
}

impl Default for Separator {
    fn default() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_default() {
        const SEPARATOR: Separator = Separator::default();
        let separator: Separator = Default::default();
        assert_eq!(SEPARATOR, separator);
    }
}
