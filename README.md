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


## Warning

This library does *not* care about expiry relative to system time.

If you want to handle expiry, you must do so yourself.

Yes, this is a very dangerous decision for cryptography code.

The intended usage for this code, working with
real-world-computer-generated GPG signatures, is an unusual area of 
security in that many users will not care about expiry, or will be
interested in validating against alternative clocks or time windows.

The author does not want to facilitate or encourage this, but respect
that it is the decision for many users, including the system the author
is integrating against.


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


I was using the `gpgme` API, which works, but the API is painful,
and the linking/requirements are complicated.

`sequoia`'s license is wrong.

`rpgp` has too many features, although it does seem to be nicely split into crates.


## Minimum Supported Rust Version (MSRV)

This crate is not testing an MSRV at this time, as `clap` (used only in
examples) is not doing MSRV. If anyone has a use-case, please raise an issue,
and I'll see if `clap` has improved, or if there's a convenient way to CI
an older release, without `clap`.

MSRV bumps are some kind of semver bump, to be decided for `1.0.0`.


## License

Licensed under either of

 * Apache License, Version 2.0
 * MIT license

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
