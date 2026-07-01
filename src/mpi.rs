use num::bigint::BigUint;
use num::integer::Integer;

#[inline]
pub fn pow_mod(val: &[u8], exp: &[u8], modulus: &[u8]) -> BigUint {
    let modulus = BigUint::from_bytes_be(modulus);
    let exp = BigUint::from_bytes_be(exp);

    assert!(modulus.is_odd());
    assert!(exp.is_odd());

    BigUint::from_bytes_be(val).modpow(&exp, &modulus)
}

#[inline]
pub fn eq(left: &BigUint, right: &[u8]) -> bool {
    BigUint::from_bytes_be(right).eq(left)
}

#[cfg(test)]
mod tests {
    use num::Zero;
    use num::bigint::BigUint;

    #[test]
    fn powm() {
        assert_eq!(
            &[125],
            super::pow_mod(&[5], &[3], &[255]).to_bytes_be().as_slice()
        );
        // (259^3) % 513 == 283
        assert_eq!(
            &[1, 211],
            super::pow_mod(&[1, 7], &[3], &[2, 1])
                .to_bytes_be()
                .as_slice()
        );
    }

    #[test]
    fn empty_vec() {
        assert!(BigUint::from_bytes_be(&[]).is_zero());
    }
}
