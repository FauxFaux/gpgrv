extern crate failure;
extern crate gpgrv;

use std::io;

use failure::format_err;
use failure::Error;
use failure::ResultExt;
use gpgrv::Keyring;

const FAUX_KEY: &[u8] = include_bytes!("faux.pubkey");
const INPUT_TXT: &[u8] = include_bytes!("formats/input.txt");
const INPUT_DAT: &[u8] = include_bytes!("formats/input.dat");

#[test]
fn load() -> Result<(), Error> {
    #[rustfmt::skip]
    let files = &[
        ("dat", "detach armour ", &include_bytes!("formats/output.dat.detach-armour")[..]),
        ("dat", "detach binary ", &include_bytes!("formats/output.dat.detach-binary")[..]),
        ("dat", "inline armour ", &include_bytes!("formats/output.dat.inline-armour")[..]),
        ("dat", "inline binary ", &include_bytes!("formats/output.dat.inline-binary")[..]),
        ("txt", "detach armour ", &include_bytes!("formats/output.txt.detach-armour")[..]),
        ("txt", "detach binary ", &include_bytes!("formats/output.txt.detach-binary")[..]),
        ("txt", "inline armour ", &include_bytes!("formats/output.txt.inline-armour")[..]),
        ("txt", "inline binary ", &include_bytes!("formats/output.txt.inline-binary")[..]),
    ];

    for (input, name, file) in files {
        let mut out = Vec::with_capacity(8096);
        gpgrv::read_doc(io::Cursor::new(file), &mut out)
            .with_context(|_| format_err!("reading {} {}", input, name))?;

        drop_trailing_newline(&mut out);

        if name.starts_with("inline") {
            assert_eq!(
                out,
                match *input {
                    "dat" => &INPUT_DAT[..INPUT_DAT.len() - 1],
                    "txt" => &INPUT_TXT[..INPUT_TXT.len() - 1],
                    _ => unreachable!(),
                },
                "checking {} {}",
                input,
                name
            );
        } else {
            assert!(out.is_empty(), "detached has no data: {} {}", input, name);
        }
    }

    Ok(())
}

fn drop_trailing_newline(v: &mut Vec<u8>) {
    while !v.is_empty() && b'\n' == v[v.len() - 1] {
        v.pop();
    }
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
        assert_eq!(
            out,
            String::from_utf8(INPUT_TXT.to_vec())?.trim().as_bytes()
        );
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
