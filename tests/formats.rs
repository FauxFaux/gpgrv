extern crate gpgrv;
extern crate failure;

use std::io;

use failure::Error;
use gpgrv::Keyring;

const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const INPUT_TXT: &str = include_str!("formats/input.txt");
const INPUT_DAT: &[u8] = include_bytes!("formats/input.dat");

#[test]
fn inline_armour() -> Result<(), Error>{
    let mut keyring = Keyring::new();
    keyring.append_keys_from(io::Cursor::new(FAUX_KEY))?;
    {
        let mut out = Vec::new();
        gpgrv::verify_clearsign_armour(
            io::Cursor::new(&include_bytes!("formats/output.txt.inline-armour")[..]),
            &mut out,
            &keyring,
        )?;
        assert_eq!(out, INPUT_TXT.trim().as_bytes());
    }
    #[cfg(todo)]
    {
        let mut out = Vec::new();
        gpgrv::verify_clearsign_armour(
            io::Cursor::new(&include_bytes!("formats/output.dat.inline-armour")[..]),
            &mut out,
            &keyring,
        )?;
        assert_eq!(out, INPUT_DAT);
    }
    Ok(())
}