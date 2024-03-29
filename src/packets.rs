use std::io;
use std::io::Read;
use std::u16;
use std::u32;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Error;
use byteorder::{BigEndian, LittleEndian};
use byteorder::ByteOrder;
use byteorder::ReadBytesExt;
use digest::Digest;

use crate::HashAlg;
use crate::PubKey;
use crate::PublicKeySig;

#[derive(Copy, Clone, Debug)]
enum PublicKeyAlg {
    Rsa,
    Dsa,
    Ecdsa,
    EdDsaLegacy,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SignatureType {
    Binary,
    CanonicalisedText,
    GenericCertificationUserId,
    PersonaCertificationUserId,
    CasualCertificationUserId,
    PositiveCertificationUserId,
    SubkeyBinding,
    PrimaryKeyBinding,
    SignatureDirectlyOnKey,
    SubkeyRevocationSignature,
    CertificationRevocationSignature,
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub issuer: Option<[u8; 8]>,
    pub authenticated_data: Vec<u8>,
    pub sig: PublicKeySig,
    pub sig_type: SignatureType,
    pub hash_alg: HashAlg,
    pub hash_hint: u16,
}

#[derive(Clone, Debug)]
pub struct PubKeyPacket {
    version: u8,
    creation_time: u32,
    pub math: PubKey,
}

#[derive(Debug, Copy, Clone)]
pub struct OnePassHelper {
    pub signature_type: SignatureType,
    pub hash_type: HashAlg,
    pub pubkey_type: (),
    pub pubkey_id: u64,
}

#[derive(Debug, Copy, Clone)]
pub enum PlainFormat {
    Binary,
    Text,
    Utf8,
}

#[derive(Debug, Clone)]
pub struct PlainData {
    format: PlainFormat,
    name: Vec<u8>,
    mtime: u32,
}

#[derive(Debug, Clone)]
pub enum Packet {
    IgnoredJunk,
    PubKey(PubKeyPacket),
    Signature(Signature),
    OnePassHelper(OnePassHelper),
}

pub enum Event<'e> {
    Packet(Packet),
    PlainData(PlainData, &'e mut dyn Read),
}

impl PubKeyPacket {
    pub fn fingerprint(&self) -> Option<[u8; 20]> {
        let (alg, len) = match self.math {
            PubKey::Rsa { ref n, ref e } => (1u8, 2 + 2 + n.len() + e.len()),
            _ => return None,
        };

        // https://tools.ietf.org/html/rfc4880#section-12.2

        let mut digest = ::sha1::Sha1::default();
        digest.update(&[0x99]);
        digest.update(&to_be_u16(1 + 4 + 1 + len));
        digest.update(&[self.version]);
        digest.update(&be_u32(self.creation_time));
        digest.update(&[alg]);
        match self.math {
            PubKey::Rsa { ref n, ref e } => {
                digest_mpi(&mut digest, n);
                digest_mpi(&mut digest, e);
            }
            _ => unreachable!(),
        }

        let mut ret = [0u8; 20];
        ret.copy_from_slice(&digest.finalize());
        Some(ret)
    }

    pub fn identity(&self) -> Option<u64> {
        self.fingerprint().map(|x| BigEndian::read_u64(&x[12..]))
    }

    pub fn identity_hex(&self) -> String {
        match self.identity() {
            // TODO: does this endian correctly?
            Some(identity) => format!("{:08x}", identity),
            None => "[unsupported key type]".to_string(),
        }
    }
}

pub fn parse_packets<R: Read, F>(mut from: R, into: &mut F) -> Result<bool, Error>
where
    F: FnMut(Event) -> Result<(), Error>,
{
    loop {
        let first_byte = match from.read_u8() {
            Ok(val) => val,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(other) => bail!(other),
        };

        parse_packet(first_byte, &mut from, into)?;
    }
}

pub fn parse_packet<R: Read, F>(first_byte: u8, mut from: R, into: &mut F) -> Result<(), Error>
where
    F: FnMut(Event) -> Result<(), Error>,
{
    let val = first_byte;

    ensure!(is_bit_set(val, 7), "invalid packet tag");
    let tag;
    let len;

    // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-packet-headers
    if is_bit_set(val, 6) {
        // "openpgp" format
        tag = val & 0b0011_1111;
        let b1 = from.read_u8()?;
        if b1 < 192 {
            len = Some(u32::from(b1));
        } else if b1 <= 223 {
            let b2 = from.read_u8()?;
            len = Some(((u32::from(b1) - 192) << 8) + u32::from(b2) + 192);
        } else if b1 == 255 {
            len = Some(from.read_u32::<BigEndian>()?);
        } else {
            bail!("unsupported variable length encoding: {b1}");
        }
    } else {
        // "legacy" format
        tag = (val & 0b0011_1100) >> 2;
        let len_code = val & 0b0000_0011;
        len = match len_code {
            0 => Some(u32::from(from.read_u8()?)),
            1 => Some(u32::from(from.read_u16::<BigEndian>()?)),
            2 => Some(from.read_u32::<BigEndian>()?),
            3 => None,
            _ => unreachable!(),
        };
    }

    let mut from = from.take(len.map(u64::from).unwrap_or(u64::max_value()));

    // https://tools.ietf.org/html/rfc4880#section-4.3
    match tag {
        0 => bail!("reserved tag: 0"),
        1 => bail!("not supported: public key encrypted session key"),
        2 => into(Event::Packet(Packet::Signature(
            parse_signature_packet(&mut from).with_context(|| "parsing signature")?,
        )))?,
        3 => bail!("not supported: symmetric key encrypted session key"),
        4 => into(Event::Packet(Packet::OnePassHelper(parse_one_pass_helper(
            &mut from,
        )?)))?,
        5 => bail!("not supported: secret key"),
        // 6: public key
        // 14: public subkey
        6 | 14 => into(Event::Packet(Packet::PubKey(parse_pubkey_packet(
            &mut from,
        )?)))?,
        7 => bail!("not supported: secret subkey"),
        8 => parse_compressed_packet(&mut from, into)?,
        9 => bail!("not supported: symmetrically encrypted data"),
        10 => bail!("not supported: marker"),
        11 => {
            let header = parse_literal_data(&mut from)?;
            into(Event::PlainData(header, &mut from))?;
        }
        // 12: admin's specified trust information
        // 13: user id (textual name)
        // 14: public subkey (handled above)
        // 15: not defined
        // 16: not defined
        // 17: extended user id (non-textual name information, e.g. image)
        12 | 13 | 17 => {
            let wanted = u64::try_from(match len {
                Some(len) => len,
                None => bail!("indeterminate length {} not supported", tag),
            })?;
            let found = io::copy(&mut from, &mut iowrap::Ignore::new())?;
            ensure!(
                found == wanted,
                "short read discarding packet: {}, found: {}, wanted: {}",
                tag,
                found,
                wanted
            );
            into(Event::Packet(Packet::IgnoredJunk))?;
        }
        18 => bail!("not supported: symmetrically encrypted and maced data"),
        19 => bail!("not supported: mac"),
        other => bail!("not recognised: packet tag: {}, len: {:?}", other, len),
    };

    if len.is_some() {
        ensure!(
            0 == from.limit(),
            "parser bug: failed to read {} trailing bytes",
            from.limit()
        );
    }

    Ok(())
}

fn parse_signature_packet<R: Read>(mut from: R) -> Result<Signature, Error> {
    Ok(match from.read_u8()? {
        3 => parse_signature_packet_v3(from).with_context(|| "v3")?,
        4 => parse_signature_packet_v4(from).with_context(|| "v4")?,
        other => bail!("not supported: unrecognised signature version: {}", other),
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.2.2
fn parse_signature_packet_v3<R: Read>(mut from: R) -> Result<Signature, Error> {
    ensure!(5 == from.read_u8()?, "invalid authenticated data length");

    let mut authenticated_data = vec![0u8; 5];
    from.read_exact(&mut authenticated_data)?;

    let sig_type = sig_type(authenticated_data[0])?;
    // remaining authenticated_data: creation time

    let mut issuer = [0u8; 8];
    from.read_exact(&mut issuer)?;

    let key_alg = key_alg(from.read_u8()?)?;
    let hash_alg = hash_alg(from.read_u8()?)?;
    let hash_hint = from.read_u16::<BigEndian>()?;

    let sig = read_sig(from, key_alg)?;

    Ok(Signature {
        issuer: Some(issuer),
        authenticated_data,
        sig,
        sig_type,
        hash_hint,
        hash_alg,
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.2.3
fn parse_signature_packet_v4<R: Read>(mut from: R) -> Result<Signature, Error> {
    let mut authenticated_data = Vec::with_capacity(32);
    authenticated_data.push(4);
    authenticated_data.resize(6, 0);
    from.read_exact(&mut authenticated_data[1..6])?;

    let sig_type = sig_type(authenticated_data[1])?;
    let key_alg = key_alg(authenticated_data[2])?;
    let hash_alg = hash_alg(authenticated_data[3])?;

    let good_subpackets_len = BigEndian::read_u16(&authenticated_data[4..6]);
    let good_subpackets_end = authenticated_data.len() + usize::try_from(good_subpackets_len)?;
    authenticated_data.resize(good_subpackets_end, 0);
    from.read_exact(&mut authenticated_data[6..])?;

    let bad_subpackets = read_u16_prefixed_data(&mut from)?;

    let issuer = find_issuer(&bad_subpackets)
        .with_context(|| "reading unsigned subpackets to determine issuer")?;

    let hash_hint = from.read_u16::<BigEndian>()?;

    let sig = read_sig(from, key_alg)?;

    Ok(Signature {
        issuer,
        authenticated_data,
        sig,
        sig_type,
        hash_hint,
        hash_alg,
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.2.1
fn sig_type(code: u8) -> Result<SignatureType, Error> {
    Ok(match code {
        0x00 => SignatureType::Binary,
        0x01 => SignatureType::CanonicalisedText,
        0x10 => SignatureType::GenericCertificationUserId,
        0x11 => SignatureType::PersonaCertificationUserId,
        0x12 => SignatureType::CasualCertificationUserId,
        0x13 => SignatureType::PositiveCertificationUserId,
        0x18 => SignatureType::SubkeyBinding,
        0x19 => SignatureType::PrimaryKeyBinding,
        0x1f => SignatureType::SignatureDirectlyOnKey,
        0x28 => SignatureType::SubkeyRevocationSignature,
        0x30 => SignatureType::CertificationRevocationSignature,
        other => bail!("not supported: signature type: 0x{:02x}", other),
    })
}

// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-public-key-algorithms
fn key_alg(code: u8) -> Result<PublicKeyAlg, Error> {
    Ok(match code {
        1 | 3 => PublicKeyAlg::Rsa,
        2 => bail!("not supported: key algorithm: rsa encrypt-only"),
        16 => bail!("not supported: key algorithm: elgamal"),
        17 => PublicKeyAlg::Dsa,
        18 => bail!("not supported: key algorithm: ecdh public key"),
        19 => PublicKeyAlg::Ecdsa,
        20 | 21 => bail!("not supported: key algorithm: [reserved]"),
        22 => PublicKeyAlg::EdDsaLegacy,
        other => bail!("not supported: key algorithm: {}", other),
    })
}

// https://tools.ietf.org/html/rfc4880#section-9.4
fn hash_alg(code: u8) -> Result<HashAlg, Error> {
    Ok(match code {
        1 => HashAlg::Md5,
        2 => HashAlg::Sha1,
        3 => HashAlg::RipeMd,
        8 => HashAlg::Sha256,
        9 => HashAlg::Sha384,
        10 => HashAlg::Sha512,
        11 => HashAlg::Sha224,
        other => bail!("not supported: hash algorithm: {}", other),
    })
}

fn read_sig<R: Read>(mut from: R, key_alg: PublicKeyAlg) -> Result<PublicKeySig, Error> {
    Ok(match key_alg {
        PublicKeyAlg::Rsa => PublicKeySig::Rsa(read_mpi(&mut from)?),
        PublicKeyAlg::Dsa => PublicKeySig::Dsa {
            r: read_mpi(&mut from)?,
            s: read_mpi(&mut from)?,
        },
        PublicKeyAlg::Ecdsa => PublicKeySig::Ecdsa {
            r: read_mpi(&mut from)?,
            s: read_mpi(&mut from)?,
        },
        PublicKeyAlg::EdDsaLegacy => PublicKeySig::EdDsaLegacy {
            r: read_mpi(&mut from)?,
            s: read_mpi(&mut from)?,
        },
    })
}

fn parse_pubkey_packet<R: Read>(mut from: R) -> Result<PubKeyPacket, Error> {
    // https://tools.ietf.org/html/rfc4880#section-5.5.2
    match from.read_u8()? {
        3 => bail!("not supported: version 3 key packets"),
        4 => {}
        other => bail!("not supported: unrecognised key packet version: {}", other),
    }

    let creation_time = from.read_u32::<BigEndian>()?;

    let math = match from.read_u8()? {
        1 => PubKey::Rsa {
            n: read_mpi(&mut from)?,
            e: read_mpi(&mut from)?,
        },
        16 => PubKey::Elgaml {
            p: read_mpi(&mut from)?,
            g: read_mpi(&mut from)?,
            y: read_mpi(&mut from)?,
        },
        17 => PubKey::Dsa {
            p: read_mpi(&mut from)?,
            q: read_mpi(&mut from)?,
            g: read_mpi(&mut from)?,
            y: read_mpi(&mut from)?,
        },
        18 => PubKey::Ecdh {
            oid: read_oid(&mut from)?,
            point: read_mpi(&mut from)?,
            // not an oid, but same format
            kdf: read_oid(&mut from)?,
        },
        19 => PubKey::Ecdsa {
            oid: read_oid(&mut from)?,
            point: read_mpi(&mut from)?,
        },
        22 => PubKey::Ed25519 {
            oid: read_oid(&mut from)?,
            point: read_mpi(&mut from)?,
        },
        other => bail!("not supported: unrecognised key type: {}", other),
    };

    Ok(PubKeyPacket {
        version: 4,
        creation_time,
        math,
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.6
fn parse_compressed_packet<R: Read, F>(mut from: R, into: &mut F) -> Result<(), Error>
where
    F: FnMut(Event) -> Result<(), Error>,
{
    // https://tools.ietf.org/html/rfc4880#section-9.3
    match from.read_u8()? {
        0 => bail!("not supported: uncompressed compression"),
        1 => (),
        2 => bail!("not supported: zlib compression"),
        3 => bail!("not supported: bzip2 compression"),
        other => bail!("not recognised: {} compression mode", other),
    }
    let mut dec = libflate::deflate::Decoder::new(from);
    parse_packets(Box::new(&mut dec) as Box<dyn Read>, into)?;
    Ok(())
}

// https://tools.ietf.org/html/rfc6637#section-9
fn read_oid<R: Read>(mut from: R) -> Result<Vec<u8>, Error> {
    let oid_len = from.read_u8()?;
    ensure!(0 != oid_len && 0xff != oid_len, "reserved oid lengths");
    let mut oid = vec![0u8; usize::from(oid_len)];
    from.read_exact(&mut oid)?;
    Ok(oid)
}

// https://tools.ietf.org/html/rfc4880#section-5.2.4.1
fn find_issuer(subpackets: &[u8]) -> Result<Option<[u8; 8]>, Error> {
    let mut issuer = None;

    for (id, data) in parse_subpackets(subpackets)? {
        if is_bit_set(id, 7) {
            bail!("unsupported critical subpacket: {}", id & 0b0111_1111);
        }

        match id {
            16 => {
                ensure!(
                    8 == data.len(),
                    "invalid issuer packet length: {}",
                    data.len()
                );
                let mut array_sadness = [0u8; 8];
                array_sadness.copy_from_slice(data);

                issuer = Some(array_sadness);
            }
            _ => {
                // SHOULD ignore non-critical
            }
        }
    }

    Ok(issuer)
}

// https://tools.ietf.org/html/rfc4880#section-5.2.3.1
fn parse_subpackets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut ret = Vec::with_capacity(data.len() / 4);

    while !data.is_empty() {
        // https://tools.ietf.org/html/rfc4880#section-5.2.3.1
        let len;
        let len_len;

        if data[0] < 192 {
            len_len = 1;
            len = usize::from(data[0]);
        } else if data[0] < 255 {
            len_len = 2;
            len = (usize::from(data[0] - 192) << 8) + usize::from(data[1]) + 192;
        } else {
            assert_eq!(255, data[0]);
            len_len = 5;
            len = usize::try_from(BigEndian::read_u32(&data[1..5]))?;
        }

        ensure!(len != 0, "illegal empty subpacket");

        // data starts after the length and the id (one byte)
        let data_start = len_len + 1;

        // `len` includes the id byte, but not the stored length; so take the id byte off
        let data_end = data_start + len - 1;

        ensure!(data.len() >= data_start, "illegal super-short subpacket");
        ensure!(data_end <= data.len(), "packet extends outside field");

        let id = data[len_len];
        ret.push((id, &data[data_start..data_end]));

        data = &data[data_end..];
    }

    Ok(ret)
}

// https://tools.ietf.org/html/rfc4880#section-5.9
fn parse_literal_data<R: Read>(mut from: R) -> Result<PlainData, Error> {
    let format = match from.read_u8()? {
        b'b' => PlainFormat::Binary,
        b't' => PlainFormat::Text,
        b'u' => PlainFormat::Utf8,
        other => bail!("unrecognised plain format: {}", other),
    };

    let name_len = from.read_u8()?;
    let mut name = vec![0u8; usize::try_from(name_len)?];
    from.read_exact(&mut name)?;
    let mtime = from.read_u32::<BigEndian>()?;
    Ok(PlainData {
        format,
        name,
        mtime,
    })
}

// https://tools.ietf.org/html/rfc4880#section-5.4
fn parse_one_pass_helper<R: Read>(mut from: R) -> Result<OnePassHelper, Error> {
    match from.read_u8()? {
        3 => (),
        other => bail!("unsupported one pass version: {}", other),
    };

    let signature_type = sig_type(from.read_u8()?)?;
    let hash_type = hash_alg(from.read_u8()?)?;
    let pubkey_type = match from.read_u8()? {
        1 => (),
        other => bail!("not supported: one pass pub key: {}", other),
    };
    let pubkey_id = from.read_u64::<BigEndian>()?;
    let _nested_flag = from.read_u8()?;

    Ok(OnePassHelper {
        signature_type,
        hash_type,
        pubkey_type,
        pubkey_id,
    })
}

fn read_u16_prefixed_data<R: Read>(mut from: R) -> Result<Vec<u8>, Error> {
    let len = from.read_u16::<BigEndian>()?;
    let mut data = vec![0u8; usize::try_from(len)?];
    from.read_exact(&mut data)?;
    Ok(data)
}

/// <https://tools.ietf.org/html/rfc4880#section-3.2>
fn read_mpi<R: Read>(mut from: R) -> Result<Vec<u8>, Error> {
    let bits: u16 = from.read_u16::<BigEndian>()?;
    if 0 == bits {
        // TODO: Is this a valid encoding?
        return Ok(Vec::new());
    }

    let bytes = (u32::from(bits) + 7) / 8;
    let mut data = vec![0u8; usize::try_from(bytes)?];
    from.read_exact(&mut data)?;

    let first_byte = data[0];
    let leading_bits = bits % 8;

    let first_bit_position = if 0 == leading_bits {
        0
    } else {
        (8 - leading_bits) as u8
    };

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

fn top_bit(val: u8) -> u8 {
    for i in (0..8).rev() {
        if val >= (1 << i) {
            return i;
        }
    }

    panic!()
}

fn digest_mpi<D: Digest>(digest: &mut D, mpi: &[u8]) {
    assert!(mpi.len() < 8192);

    if mpi.is_empty() {
        // zero length, no data
        digest.update(&[0, 0]);
        return;
    }

    let first_byte = mpi[0];
    assert_ne!(0, first_byte, "invalid mpi: zero prefix");
    let bytes_len = (mpi.len() - 1) * 8;
    let bits_len = 1 + usize::from(top_bit(first_byte));
    let total_len = bytes_len + bits_len;

    digest.update(&to_be_u16(total_len));
    digest.update(mpi);
}

fn to_be_u16(val: usize) -> [u8; 2] {
    assert!(val <= u16::MAX as usize, "value too big for u16");
    let mut ret = [0u8; 2];
    BigEndian::write_u16(&mut ret[..], val as u16);
    ret
}

fn be_u32(val: u32) -> [u8; 4] {
    let mut ret = [0u8; 4];
    BigEndian::write_u32(&mut ret[..], val);
    ret
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
    use std::io::Cursor;
    use std::io::Read;

    use anyhow::Error;

    use super::parse_packets;
    use super::Event;
    use super::Packet;

    const EMPTY_SIG: &[u8] = include_bytes!("../tests/smoke/empty-message.inline-sig");
    const FAUX_KEY: &[u8] = include_bytes!("../tests/faux.pubkey");

    #[test]
    fn mpi() {
        use super::read_mpi;
        assert_eq!(vec![0x01], read_mpi(Cursor::new(vec![0, 1, 0x01])).unwrap());
        assert_eq!(
            vec![0x01, 0xff],
            read_mpi(Cursor::new(vec![0, 9, 0x01, 0xff])).unwrap()
        );

        assert_eq!(vec![0xff], read_mpi(Cursor::new(vec![0, 8, 0xff])).unwrap());

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

    #[test]
    fn bit() {
        use super::top_bit;
        assert_eq!(0, top_bit(1));
        assert_eq!(1, top_bit(2));
        assert_eq!(1, top_bit(3));
        assert_eq!(2, top_bit(4));
        assert_eq!(6, top_bit(126));
        assert_eq!(6, top_bit(127));
        assert_eq!(7, top_bit(128));
    }

    #[test]
    fn packets_sig() -> Result<(), Error> {
        match parse_to_list(Cursor::new(EMPTY_SIG))?.into_iter().next() {
            Some(Packet::Signature(sig)) => assert!(sig.issuer.is_some()),
            _ => panic!("wrong type of/missing packet"),
        }
        Ok(())
    }

    #[test]
    fn packets_key() -> Result<(), Error> {
        match parse_to_list(Cursor::new(FAUX_KEY))?.into_iter().next() {
            Some(Packet::PubKey(key)) => match key {
                _ => {
                    assert_eq!("b195e1c4779ba9b2", key.identity_hex());
                }
            },
            _ => panic!("wrong type of/missing packet"),
        }
        Ok(())
    }

    fn parse_to_list<R: Read>(from: R) -> Result<Vec<Packet>, Error> {
        let mut ret = Vec::new();
        parse_packets(from, &mut |ev| {
            match ev {
                Event::Packet(p) => ret.push(p),
                Event::PlainData(_, _) => panic!("data"),
            }
            Ok(())
        })?;
        Ok(ret)
    }
}
