use crate::rsa;
use crate::Digestable;
use crate::Keyring;
use crate::PubKey;
use crate::PublicKeySig;
use crate::Signature;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature is not correct.
    Mismatch,

    /// The signature hint is not correct. This means that the data was corrupted,
    /// or that it was canonicalised incorrectly.
    HintMismatch,

    /// We don't have the key the signature asks for.
    NoKey,

    /// The signature or key contains recognised, but invalid, data.
    BadData,

    /// The signature or key uses an algorithm that is not currently supported.
    UnsupportedAlgorithm,

    /// The key and signature are of incompatible types.
    KeySignatureIncompatible,

    /// The signature lacked the (optional) `issuer` field. This is not supported.
    NoIssuer,
}

pub fn is_any_signature_valid<'s, S: IntoIterator<Item = &'s Signature>>(
    keyring: &Keyring,
    sigs: S,
    digest: &Digestable,
) -> bool {
    any_signature_valid(keyring, sigs, digest).is_ok()
}

pub fn any_signature_valid<'s, S: IntoIterator<Item = &'s Signature>>(
    keyring: &Keyring,
    sigs: S,
    digest: &Digestable,
) -> Result<(), Vec<SignatureError>> {
    let mut errors = Vec::with_capacity(4);
    for sig in sigs {
        match single_signature_valid(keyring, sig, digest.clone()) {
            Ok(()) => return Ok(()),
            Err(e) => errors.extend(e),
        }
    }

    Err(errors)
}

fn single_signature_valid(
    keyring: &Keyring,
    sig: &Signature,
    mut digest: Digestable,
) -> Result<(), Vec<SignatureError>> {
    digest.process(&sig.authenticated_data);

    let len = match u32::try_from(sig.authenticated_data.len()) {
        Ok(len) => len,
        Err(_) => return Err(vec![SignatureError::BadData]),
    };

    digest.process(&make_tail(len));

    let hash = digest.clone().hash();

    if sig.hash_hint.to_be_bytes() != hash[..2] {
        return Err(vec![SignatureError::HintMismatch]);
    }

    let padded_hash = match sig.sig {
        PublicKeySig::Rsa(ref sig) => digest
            .emsa_pkcs1_v1_5(&hash, sig.len())
            .ok_or_else(|| vec![SignatureError::BadData])?,
        _ => return Err(vec![SignatureError::UnsupportedAlgorithm]),
    };

    let keys = keyring.keys_with_id(u64::from_be_bytes(
        sig.issuer.ok_or_else(|| vec![SignatureError::NoIssuer])?,
    ));

    if keys.is_empty() {
        return Err(vec![SignatureError::NoKey]);
    }

    let mut errors = Vec::with_capacity(keys.len());

    for key in keys {
        match single_signature_key_valid(key, &sig.sig, &padded_hash) {
            Ok(()) => return Ok(()),
            Err(e) => errors.push(e),
        }
    }

    Err(errors)
}

fn single_signature_key_valid(
    key: &PubKey,
    sig: &PublicKeySig,
    padded_hash: &[u8],
) -> Result<(), SignatureError> {
    match *key {
        PubKey::Rsa { ref n, ref e } => match *sig {
            PublicKeySig::Rsa(ref sig) => rsa::verify(sig, (n, e), padded_hash),
            _ => Err(SignatureError::KeySignatureIncompatible),
        },
        PubKey::Ecdsa { .. } => Err(SignatureError::UnsupportedAlgorithm),
        PubKey::Ed25519 { .. } => Err(SignatureError::UnsupportedAlgorithm),
        PubKey::Dsa { .. } => Err(SignatureError::UnsupportedAlgorithm),
        // Elgaml doesn't support signing
        PubKey::Elgaml { .. } => Err(SignatureError::BadData),
    }
}

fn make_tail(len: u32) -> [u8; 6] {
    let mut tail = [0u8; 6];
    tail[0] = 0x04;
    tail[1] = 0xff;
    tail[2..].copy_from_slice(&len.to_be_bytes());
    tail
}
