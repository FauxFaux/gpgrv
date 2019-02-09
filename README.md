# gpgrv 

[![](https://img.shields.io/crates/v/gpgrv.svg)](https://crates.io/crates/gpgrv)
[![](https://travis-ci.org/FauxFaux/gpgrv.svg)](https://travis-ci.org/FauxFaux/gpgrv)

![An RV.](gpgrv.jpg)

`gpgrv` is a Rust library for verifying some types of GPG signatures.


```rust
use std::io::{stdin, stdout, BufReader, Cursor, Seek, SeekFrom};
fn main() {
    // load a keyring from some file(s)
    // for example, we use the linux distribution keyring
    let mut keyring = gpgrv::Keyring::new();
    let keyring_file = Cursor::new(distro_keyring::supported_keys());
    keyring.append_keys_from(keyring_file).unwrap();

    // read stdin, verify, and write the output to a temporary file
    let mut temp = tempfile::tempfile().unwrap();
    gpgrv::verify_message(BufReader::new(stdin()), &mut temp, &keyring).expect("verification");

    // if we succeeded, print the temporary file to stdout
    temp.seek(SeekFrom::Start(0)).unwrap();
    std::io::copy(&mut temp, &mut stdout()).unwrap();
}
```

## Supports

 * Verifying signatures:
   * `RSA`
   * `SHA1` and `SHA2` (`SHA-256`, `SHA-512`).
 * Signed "inline" messages, and detached signatures.
 * Armoured and unarmoured/binary.
 * Compression wrappers (added by `gpg` for most messages)
 * Loading old-style keyrings (i.e. not keybox files)


## Advantages

 * Entirely safe Rust, no native code. Easy to build and portable.
 * MIT (or Apache2, or whatever!) licensed, not LGPL.
 * Simple, Rust-style API on streams (`Read`/`Write`).


## Disadvantages

 * A tiny amount of custom, low-risk crypto code.
   However, any crypto code can be wrong.
 * Limited, but growing, support for key and data formats.
 * (Intentionally) not constant time: Cannot be used for certain crypto
   applications. This is less important for signature verification with
   public keys.


## Alternatives

 * [`gpgme`](https://crates.io/crates/gpgme) (LGPL) - bindings for native code, verbose API
 * [`rpgp`](https://github.com/dignifiedquire/rpgp) (MIT/Apache2) - serious implementation of plenty of `pgp`
 * [`sequoia-openpgp`](https://crates.io/crates/sequoia-openpgp) (GPLv3) - serious implementation of plenty of `pgp` 


I was using the the `gpgme` API, which works, but the API is painful,
and the linking/requirements are complicated.

`sequoia`'s license is wrong.

`rpgp` has too many features, although it does seem to be nicely split into crates.


## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
