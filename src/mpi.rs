use gmp::mpz::Mpz;

#[inline]
pub fn pow_mod(val: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    Vec::from(&Mpz::from(val).powm(&Mpz::from(exp), &Mpz::from(modulus)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn powm() {
        assert_eq!(&[9], super::pow_mod(&[7], &[2], &[40]).as_slice());
        // (259^3) % 512 == 283
        assert_eq!(&[1, 27], super::pow_mod(&[1, 3], &[3], &[2, 0]).as_slice());
    }
}
