use errors::*;

use mpi;

pub fn verify(sig: &[u8], (n, e): (&[u8], &[u8]), padded_hash: &[u8]) -> Result<()> {
    ensure!(
        mpi::pow_mod(sig, &e, &n) == padded_hash,
        "signature mismatch!"
    );

    Ok(())
}
