# `itsdangerous-rs`

[![Build Status](https://travis-ci.org/discordapp/itsdangerous-rs.svg?branch=master)](https://travis-ci.org/discordapp/itsdangerous-rs)
[![License](https://img.shields.io/github/license/discordapp/itsdangerous-rs.svg)](LICENSE)
[![Documentation](https://docs.rs/itsdangerous/badge.svg)](https://docs.rs/itsdangerous)
[![Cargo](https://img.shields.io/crates/v/itsdangerous.svg)](https://crates.io/crates/itsdangerous)

A rust re-implementation of the Python library [itsdangerous](https://github.com/pallets/itsdangerous/).

Essentially, this crate provides various helpers to pass data to untrusted environments
and get it back safe and sound. Data is cryptographically signed to ensure that it has
not been tampered with.

## Basic Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
itsdangerous = "0.1"
```

Next, get to signing some dangerous strings:

```rust
use itsdangerous::{default_builder, Signer};

fn main() {
    // Create a signer using the default builder, and an arbitrary secret key.
    let signer = default_builder("secret key").build();

    // Sign an arbitrary string, and send it somewhere dangerous.
    let signed = signer.sign("hello world!");

    // Unsign the string and validate that it hasn't been tampered with.
    let unsigned = signer.unsign(&signed).expect("Signature was not valid");
    assert_eq!(unsigned, "hello world!");
}
```

For more in-depth examples, check out the [documentation](https://docs.rs/itsdangerous)!

## License

Licensed under the [MIT license](LICENSE).
