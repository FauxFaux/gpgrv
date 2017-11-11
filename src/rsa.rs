use errors::*;

use mpi;

pub struct PubKey {
    n: Vec<u8>,
    e: u32,
}

pub fn verify(sig: &[u8], key: &PubKey, padded_hash: &[u8]) -> Result<()> {
    ensure!(mpi::pow_mod(sig, key.e, &key.n) == padded_hash, "signature mismatch!");

    Ok(())
}
