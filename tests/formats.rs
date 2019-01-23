extern crate failure;
extern crate gpgrv;

use std::io;

use failure::format_err;
use failure::Error;
use failure::ResultExt;
use gpgrv::Keyring;

const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const INPUT_TXT: &str = include_str!("formats/input.txt");
const INPUT_DAT: &[u8] = include_bytes!("formats/input.dat");

#[test]
fn load() -> Result<(), Error> {
    #[rustfmt::skip]
    let files = &[
        ("dat detach armour ", &include_bytes!("formats/output.dat.detach-armour")[..]),
        ("dat detach binary ", &include_bytes!("formats/output.dat.detach-binary")[..]),
        ("dat inline armour ", &include_bytes!("formats/output.dat.inline-armour")[..]),
        // ("dat inline binary ", &include_bytes!("formats/output.dat.inline-binary")[..]),
        ("txt detach armour ", &include_bytes!("formats/output.txt.detach-armour")[..]),
        ("txt detach binary ", &include_bytes!("formats/output.txt.detach-binary")[..]),
        ("txt inline armour ", &include_bytes!("formats/output.txt.inline-armour")[..]),
        // ("txt inline binary ", &include_bytes!("formats/output.txt.inline-binary")[..]),
    ];

    for (name, file) in files {
        gpgrv::read_doc(io::Cursor::new(file), iowrap::Ignore::new())
            .with_context(|_| format_err!("reading {}", name))?;
    }

    Ok(())
}

#[test]
fn inline_armour() -> Result<(), Error> {
    let mut keyring = Keyring::new();
    keyring.append_keys_from(io::Cursor::new(FAUX_KEY))?;
    {
        let mut out = Vec::new();
        gpgrv::verify_message(
            io::Cursor::new(&include_bytes!("formats/output.txt.inline-armour")[..]),
            &mut out,
            &keyring,
        )?;
        assert_eq!(out, INPUT_TXT.trim().as_bytes());
    }
    #[cfg(todo)]
    {
        let mut out = Vec::new();
        gpgrv::verify_message(
            io::Cursor::new(&include_bytes!("formats/output.dat.inline-armour")[..]),
            &mut out,
            &keyring,
        )?;
        assert_eq!(out, INPUT_DAT);
    }
    Ok(())
}
