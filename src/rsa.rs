use errors::*;

use mpi;

pub fn verify(sig: &[u8], (n, e): (&[u8], &[u8]), padded_hash: &[u8]) -> Result<()> {
    let mut expected = mpi::pow_mod(sig, &e, &n);

    // Horribly inefficient, unless the compiler fixes it. But, also, should only be one byte.
    while expected.len() < padded_hash.len() {
        expected.insert(0, 0);
    }

    if expected == padded_hash {
        return Ok(());
    }

    bail!("signatures don't match");
}
