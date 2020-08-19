use std::fs;
use std::io;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Error;
use clap::App;
use clap::Arg;

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
                fs::File::open(path).with_context(|| anyhow!("opening keyring {:?}", path))?,
            )
            .with_context(|| format!("reading keyring {:?}", path))?;
    }

    for &key in keyring.key_ids() {
        println!("loaded key: {:016x}", key);
    }

    for file in matches.values_of_os("FILES").unwrap() {
        gpgrv::verify_message(
            io::BufReader::new(
                fs::File::open(file).with_context(|| anyhow!("opening input file {:?}", file))?,
            ),
            iowrap::Ignore::new(),
            &keyring,
        )
        .with_context(|| anyhow!("verifying input file {:?}", file))?;
    }

    Ok(())
}
