use errors::*;

use mpi;

pub fn verify(sig: &[u8], (n, e): (&[u8], &[u8]), padded_hash: &[u8]) -> Result<()> {
    let expected = mpi::pow_mod(sig, &e, &n);

    if mpi::eq(&expected, padded_hash) {
        return Ok(());
    }

    bail!("signatures don't match");
}
