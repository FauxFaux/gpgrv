# gpgrv 

![An RV.](gpgrv.jpg)

`gpgrv` is a Rust library for verifying some types of GPG signatures.

If you want a fully featured, supported, `C`-backed library you should probably
be using [`gpgme`](https://crates.io/crates/gpgme). 

## Supports

 * Verifying signatures:
   * `RSA`
   * `SHA1` and `SHA2` (`SHA-256`, `SHA-512`).
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
