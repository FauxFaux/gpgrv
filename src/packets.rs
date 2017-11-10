use std::io::Read;
use std::u32;

use byteorder::BigEndian;
use byteorder::ReadBytesExt;

use errors::*;
use usize_from;
use usize_from_u32;

enum PublicKeyAlg {
    Rsa,
    Dsa,
}

enum PublicKeySig {
    Rsa(Vec<u8>),
    Dsa { r: Vec<u8>, s: Vec<u8> },
}

enum HashAlg {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Signature {
    pub issuer: Option<[u8; 8]>,
    authenticated_data: Vec<u8>,
    sig: PublicKeySig,
}

pub fn parse_packet<R: Read>(mut from: R) -> Result<Signature> {
    let val = from.read_u8()?;
    ensure!(is_bit_set(val, 7), "invalid packet tag");
    let tag;
    let len;

    if is_bit_set(val, 6) {
        // new format
        tag = val & 0b0011_1111;

        bail!("not supported: new format");
    } else {
        // old format
        tag = (val & 0b0011_1100) >> 2;
        let len_code = val & 0b0000_0011;
        len = match len_code {
            0 => u32::from(from.read_u8()?),
            1 => u32::from(from.read_u16::<BigEndian>()?),
            2 => from.read_u32::<BigEndian>()?,
            3 => bail!("not supported: indeterminate length packets"),
            _ => unreachable!(),
        };
    }

    let mut from = from.take(u64::from(len));

    let parsed = match tag {
        2 => parse_signature_packet(&mut from),
        other => bail!("not supported: packet tag: {}, len: {}", other, len),
    };

    ensure!(
        0 == from.limit(),
        "parser bug: failed to read {} trailing bytes",
        from.limit()
    );

    parsed
}

fn parse_signature_packet<R: Read>(mut from: R) -> Result<Signature> {
    {
        // https://tools.ietf.org/html/rfc4880#section-5.2.3
        match from.read_u8()? {
            3 => bail!("not supported: version 3 signatures"),
            4 => {}
            other => bail!("not supported: unrecognised signature version: {}", other),
        }
    }

    {
        // https://tools.ietf.org/html/rfc4880#section-5.2.1
        let sig_type = from.read_u8()?;
        match sig_type {
            0x01 => {
                // canonicalised text document, what we're implementing
            }
            other => bail!("not supported: signature type: {}", other),
        }
    }

    // https://tools.ietf.org/html/rfc4880#section-9.1
    let key_alg = match from.read_u8()? {
        1 | 3 => PublicKeyAlg::Rsa,
        17 => PublicKeyAlg::Dsa,
        other => bail!("not supported: key algorithm: {}", other),
    };

    // https://tools.ietf.org/html/rfc4880#section-9.4
    let hash_alg = match from.read_u8()? {
        2 => HashAlg::Sha1,
        8 => HashAlg::Sha256,
        10 => HashAlg::Sha512,
        other => bail!("not supported: hash algorithm: {}", other),
    };

    let good_subpackets = read_u16_prefixed_data(&mut from)?;
    let bad_subpackets = read_u16_prefixed_data(&mut from)?;

    let issuer = find_issuer(&bad_subpackets)?;

    let hash_hint = from.read_u16::<BigEndian>();

    let sig = match key_alg {
        PublicKeyAlg::Rsa => {
            PublicKeySig::Rsa(read_mpi(&mut from)?)
        }
        PublicKeyAlg::Dsa => {
            PublicKeySig::Dsa {
                r: read_mpi(&mut from)?,
                s: read_mpi(&mut from)?,
            }
        }
    };

    Ok(Signature {
        issuer,
        authenticated_data: good_subpackets,
        sig,
    } )
}

fn find_issuer(subpackets: &[u8]) -> Result<Option<[u8; 8]>> {
    for (id, data) in parse_subpackets(&subpackets)? {
        if is_bit_set(id, 7) {
            bail!("unsupported critical subpacket: {}", id);
        }

        match id {
            16 => {
                ensure!(8 == data.len(), "invalid issuer packet length: {}", data.len());
                let mut array_sadness = [0u8; 8];
                array_sadness.copy_from_slice(data);

                // TODO: accepting the first value?
                return Ok(Some(array_sadness));
            }
            _ => {
                // SHOULD ignore non-critical
            }
        }
    }

    return Ok(None);
}

// https://tools.ietf.org/html/rfc4880#section-5.2.3.1
fn parse_subpackets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut ret = Vec::with_capacity(data.len() / 4);

    while !data.is_empty() {
        let len = usize::from(data[0]);
        ensure!(len < 192, "not supported [laziness]: long sub packets");
        ensure!(len != 0, "illegal empty subpacket");

        // data starts after the length (currently always 1 byte) and the id (one byte)
        let data_start = 1 + 1;

        // `len` includes the id byte, but not the stored length; so take the id byte off
        let data_end = data_start + len - 1;

        ensure!(data.len() >= data_start, "illegal super-short subpacket");
        ensure!(data_end <= data.len(), "packet extends outside field");

        let id = data[1];
        ret.push((id, &data[data_start..data_end]));

        data = &data[data_end..];
    }

    Ok(ret)
}

fn read_u16_prefixed_data<R: Read>(mut from: R) -> Result<Vec<u8>> {
    let len = from.read_u16::<BigEndian>()?;
    let mut data = vec![0u8; usize_from(len)];
    from.read_exact(&mut data)?;
    Ok(data)
}

/// https://tools.ietf.org/html/rfc4880#section-3.2
fn read_mpi<R: Read>(mut from: R) -> Result<Vec<u8>> {
    let bits: u16 = from.read_u16::<BigEndian>()?;
    if 0 == bits {
        // TODO: Is this a valid encoding?
        return Ok(Vec::new());
    }

    let bytes = (u32::from(bits) + 7) / 8;
    let mut data = vec![0u8; usize_from_u32(bytes)];
    from.read_exact(&mut data)?;

    let first_byte = data[0];
    let first_bit_position = (8 - (bits % 8)) as u8;

    for i in 0..first_bit_position {
        ensure!(
            !is_bit_set(first_byte, 7 - i),
            "invalid MPI encoding: leading bits must be zero"
        );
    }

    ensure!(
        is_bit_set(first_byte, 7 - first_bit_position),
        "invalid MPI encoding: first bit must be set"
    );

    Ok(data)
}

/// Check if a 0-indexed bit, counted in the traditional way, is set.
/// | 7 6 5 4 3 2 1 0 |
#[inline]
fn is_bit_set(value: u8, bit_no: u8) -> bool {
    assert!(bit_no < 8);
    (value & (1 << bit_no)) == (1 << bit_no)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Cursor;
    #[test]
    fn mpi() {
        use super::read_mpi;
        assert_eq!(vec![0x01], read_mpi(Cursor::new(vec![0, 1, 0x01])).unwrap());
        assert_eq!(
            vec![0x01, 0xff],
            read_mpi(Cursor::new(vec![0, 9, 0x01, 0xff])).unwrap()
        );

        // invalid: bit length refers to a bit that's not set
        assert!(read_mpi(Cursor::new(vec![0, 2, 0b0000_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 4, 0b0000_0111])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 8, 0b0111_1111])).is_err());

        // invalid: bits set before first bit
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b0000_0011])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b0001_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 1, 0b1000_0001])).is_err());
        assert!(read_mpi(Cursor::new(vec![0, 2, 0b0000_1010])).is_err());
    }
}
