extern crate clap;
extern crate gpgrv;
extern crate iowrap;

#[macro_use]
extern crate failure;

use std::fs;

use clap::App;
use clap::Arg;
use failure::Error;
use failure::ResultExt;

fn main() -> Result<(), Error> {
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
            .append_keys_from(
                fs::File::open(path).with_context(|_| format_err!("opening keyring {:?}", path))?,
            )
            .with_context(|_| format!("reading keyring {:?}", path))?;
    }

    for file in matches.values_of_os("FILES").unwrap() {
        gpgrv::verify_message(
            buffered_reader::BufferedReaderFile::open(file)
                .with_context(|_| format_err!("opening input file {:?}", file))?,
            iowrap::Ignore::new(),
            &keyring,
        )
        .with_context(|_| format_err!("verifying input file {:?}", file))?;
    }

    Ok(())
}
