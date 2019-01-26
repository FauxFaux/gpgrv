use byteorder::BigEndian;
use byteorder::ByteOrder;
use cast::u32;
use failure::Error;

use crate::rsa;
use crate::Digestable;
use crate::Keyring;
use crate::PubKey;
use crate::PublicKeySig;
use crate::Signature;

pub fn verify(keyring: &Keyring, sig: &Signature, mut digest: Digestable) -> Result<(), Error> {
    digest.process(&sig.authenticated_data);
    digest.process(&make_tail(sig.authenticated_data.len())?);

    let hash = digest.clone().hash();

    {
        let actual = BigEndian::read_u16(&hash);
        ensure!(
            actual == sig.hash_hint,
            "digest hint doesn't match; digest is probably wrong, exp: {:04x}, act: {:04x}",
            sig.hash_hint,
            actual,
        );
    }

    let padded_hash = match sig.sig {
        PublicKeySig::Rsa(ref sig) => digest.emsa_pkcs1_v1_5(&hash, sig.len())?,
        _ => bail!("unsupported signature"),
    };

    for key in keyring.keys_with_id(BigEndian::read_u64(
        &sig.issuer.ok_or_else(|| format_err!("missing issuer"))?,
    )) {
        if check_signature(key, &sig.sig, &padded_hash).is_ok() {
            return Ok(());
        }
    }

    bail!("no known keys could validate the signature")
}

fn check_signature(key: &PubKey, sig: &PublicKeySig, padded_hash: &[u8]) -> Result<(), Error> {
    match *key {
        PubKey::Rsa { ref n, ref e } => match *sig {
            PublicKeySig::Rsa(ref sig) => rsa::verify(sig, (n, e), padded_hash),
            _ => bail!("key/signature type mismatch"),
        },
        PubKey::Ecdsa { .. } => bail!("not implemented: verify ecdsa signatures"),
        PubKey::Ed25519 { .. } => bail!("not implemented: verify ed25519 signatures"),
        PubKey::Dsa { .. } => bail!("not implemented: verify dsa signatures"),
        PubKey::Elgaml { .. } => bail!("elgaml may not have signatures"),
    }
}

fn make_tail(len: usize) -> Result<[u8; 6], Error> {
    let mut tail = [0u8; 6];
    tail[0] = 0x04;
    tail[1] = 0xff;
    BigEndian::write_u32(&mut tail[2..], u32(len)?);
    Ok(tail)
}
