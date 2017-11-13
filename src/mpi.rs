use num_bigint::BigUint;

#[inline]
pub fn pow_mod(val: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    pre_validate_number(val);
    pre_validate_number(exp);
    pre_validate_number(modulus);
    BigUint::from_bytes_be(val)
        .modpow(
            &BigUint::from_bytes_be(exp),
            &BigUint::from_bytes_be(modulus),
        )
        .to_bytes_be()
}

#[inline]
fn pre_validate_number(val: &[u8]) {
    assert!(!val.is_empty(), "no bytes is no number");
    assert!(val.len() > 1 || val[0] != 0, "zero is not okay");
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
