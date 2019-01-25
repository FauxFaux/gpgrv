extern crate failure;
extern crate gpgrv;

use std::io;

use failure::Error;
use gpgrv::Keyring;

const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const INPUT_TXT: &[u8] = include_bytes!("formats/input.txt");
const INPUT_DAT: &[u8] = include_bytes!("formats/input.dat");

#[rustfmt::skip] #[test] fn test_dat_detach_armour() -> Result<(), Error> { check(INPUT_DAT, true,  &include_bytes!("formats/output.dat.detach-armour")[..]) }
#[rustfmt::skip] #[test] fn test_dat_detach_binary() -> Result<(), Error> { check(INPUT_DAT, true,  &include_bytes!("formats/output.dat.detach-binary")[..]) }
#[rustfmt::skip] #[test] fn test_dat_inline_armour() -> Result<(), Error> { check(INPUT_DAT, false, &include_bytes!("formats/output.dat.inline-armour")[..]) }
#[rustfmt::skip] #[test] fn test_dat_inline_binary() -> Result<(), Error> { check(INPUT_DAT, false, &include_bytes!("formats/output.dat.inline-binary")[..]) }
#[rustfmt::skip] #[test] fn test_txt_detach_armour() -> Result<(), Error> { check(INPUT_TXT, true,  &include_bytes!("formats/output.txt.detach-armour")[..]) }
#[rustfmt::skip] #[test] fn test_txt_detach_binary() -> Result<(), Error> { check(INPUT_TXT, true,  &include_bytes!("formats/output.txt.detach-binary")[..]) }
#[rustfmt::skip] #[test] fn test_txt_inline_armour() -> Result<(), Error> { check(INPUT_TXT, false, &include_bytes!("formats/output.txt.inline-armour")[..]) }
#[rustfmt::skip] #[test] fn test_txt_inline_binary() -> Result<(), Error> { check(INPUT_TXT, false, &include_bytes!("formats/output.txt.inline-binary")[..]) }

fn check(expected: &[u8], detached: bool, file: &[u8]) -> Result<(), Error> {
    let mut out = Vec::with_capacity(8096);
    let doc = gpgrv::read_doc(io::Cursor::new(file), &mut out).unwrap();

    // TODO: we currently don't get the same ending new line behaviour for:
    // TODO: * test_dat_inline_armour
    // TODO: * test_txt_inline_armour

    drop_trailing_newline(&mut out);

    if detached {
        assert_eq!(0, out.len());
    } else {
        assert_eq!(&expected[..expected.len() - 1], out.as_slice());
    }

    let mut keyring = Keyring::new();
    keyring.append_keys_from(io::Cursor::new(FAUX_KEY)).unwrap();

    Ok(())
}

fn drop_trailing_newline(v: &mut Vec<u8>) {
    while !v.is_empty() && b'\n' == v[v.len() - 1] {
        v.pop();
    }
}
