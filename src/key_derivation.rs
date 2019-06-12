use generic_array::{ArrayLength, GenericArray};
use hmac::crypto_mac::Mac;
use hmac::digest::{BlockInput, Digest, FixedOutput, Input, Reset};

/// This trait is called to derive a key for signing from a given key + salt.
///
/// ## Remarks
/// Key derivation is not indended to be used as a security method to make a
/// complex key out of a short password. Instead, you should use large random
/// secret keys.
pub trait DeriveKey {
    fn derive_key<Digest>(secret_key: &str, salt: &str) -> GenericArray<u8, Digest::OutputSize>
    where
        Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
        Digest::BlockSize: ArrayLength<u8> + Clone,
        Digest::OutputSize: ArrayLength<u8>;
}

/// Derives a key by doing `digest(salt + secret_key)`
pub struct Concat;

/// Derives a key by doing `digest(salt + "signer" + secret_key)`
pub struct DjangoConcat;

/// Derives a secret key by doing `hmac<digest>(secret_key, input=salt)`
pub struct Hmac;

macro_rules! derive_key_impl {
    ($type:ty, ($secret_key:ident, $salt:ident) => $impl: block) => {
        impl DeriveKey for $type {
            fn derive_key<Digest>(
                $secret_key: &str,
                $salt: &str,
            ) -> GenericArray<u8, Digest::OutputSize>
            where
                Digest: Input + BlockInput + FixedOutput + Reset + Default + Clone,
                Digest::BlockSize: ArrayLength<u8> + Clone,
                Digest::OutputSize: ArrayLength<u8>,
            {
                $impl
            }
        }
    };
}

derive_key_impl!(Concat, (secret_key, salt) => {
    let mut digest = Digest::new();
    digest.input(salt.as_bytes());
    digest.input(secret_key.as_bytes());
    digest.result()
});

derive_key_impl!(DjangoConcat, (secret_key, salt) => {
    let mut digest = Digest::new();
    digest.input(salt.as_bytes());
    digest.input("signer".as_bytes());
    digest.input(secret_key.as_bytes());
    digest.result()
});

derive_key_impl!(Hmac, (secret_key, salt) => {
    let mut mac: hmac::Hmac<Digest> =
        hmac::Hmac::new_varkey(secret_key.as_bytes()).unwrap();
    mac.input(salt.as_bytes());
    mac.result().code()
});
