use crate::base64;
use crate::error::{InvalidSeperator, SeperatorNotFound};

/// A seperator character that can be used in [`crate::SignerBuilder::with_seperator`].
///
/// This is used to join the various parts of the signed payload.
///
/// # Basic Usage
/// ```rust
/// use itsdangerous::{default_builder, Seperator};
///
/// // Creates a seperator using a given character.
/// let seperator = Seperator::new('!').expect("Invalid seperator :(");
/// // Use that seperator in the builder.
/// let signer = default_builder("hello")
///     .with_seperator(seperator)
///     .build();
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Seperator(pub(crate) char);

impl Seperator {
    /// Creates a new seperator, checking to make sure it is valid.
    ///
    /// A valid seperator is a character that is not in the
    /// base-64 url-safe alphabet.
    pub fn new(seperator: char) -> Result<Self, InvalidSeperator> {
        if base64::in_alphabet(seperator) {
            Err(InvalidSeperator(seperator))
        } else {
            Ok(Self(seperator))
        }
    }

    #[inline(always)]
    pub fn split<'a>(&self, value: &'a str) -> Result<(&'a str, &'a str), SeperatorNotFound> {
        let mut iterator = value.rsplitn(2, self.0);
        let second = iterator.next().unwrap();
        let first = match iterator.next() {
            None => return Err(SeperatorNotFound { seperator: *self }),
            Some(val) => val,
        };
        Ok((first, second))
    }
}

impl Default for Seperator {
    fn default() -> Self {
        Self('.')
    }
}
