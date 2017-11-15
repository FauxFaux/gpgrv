extern crate clap;
extern crate gpgrv;

#[macro_use]
extern crate error_chain;

use errors::*;

use std::fs;
use std::io;

use clap::App;
use clap::Arg;

quick_main!(run);

fn run() -> Result<()> {
    let matches = App::new("gpgv")
        .arg(
            Arg::with_name("keyring")
                .long("keyring")
                .value_name("FILE")
                .multiple(true)
                .required(true)
                .number_of_values(1)
                .help("take the keys from the keyring FILE"),
        )
        .arg(
            Arg::with_name("FILES")
                .multiple(true)
                .required(true)
                .index(1)
                .help("files to verify"),
        )
        .get_matches();

    let mut keyring = gpgrv::Keyring::new();
    for path in matches.values_of_os("keyring").unwrap() {
        keyring
            .append_keys_from(fs::File::open(path)
                .chain_err(|| format!("opening keyring {:?}", path))?)
            .chain_err(|| format!("reading keyring {:?}", path))?;
    }

    for file in matches.values_of_os("FILES").unwrap() {
        gpgrv::verify_clearsign_armour(
            io::BufReader::new(fs::File::open(file)
                .chain_err(|| format!("opening input file {:?}", file))?),
            io::Cursor::new(vec![]),
            &keyring,
        ).chain_err(|| format!("verifying input file {:?}", file))?;
    }

    Ok(())
}

mod errors {
    error_chain! {
        links {
            Gpgrv(::gpgrv::Error, ::gpgrv::ErrorKind);
        }

        foreign_links {
            Io(::std::io::Error);
        }
    }
}
