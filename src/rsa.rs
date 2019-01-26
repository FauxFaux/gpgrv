use crate::mpi;
use crate::verify::SignatureError;

pub fn verify(
    sig: &[u8],
    (n, e): (&[u8], &[u8]),
    padded_hash: &[u8],
) -> Result<(), SignatureError> {
    if sig.len() < (2048 / 8) {
        // signature too short
        return Err(SignatureError::BadData);
    }

    let expected = mpi::pow_mod(sig, e, n);

    if mpi::eq(&expected, padded_hash) {
        return Ok(());
    }

    Err(SignatureError::Mismatch)
}
