use std::fs;
use std::io;

use anyhow::{anyhow, Context, Error, Result};
use clap::{Arg, ArgAction};

fn main() -> Result<()> {
    let matches = clap::command!()
        .arg(
            Arg::new("keyring")
                .long("keyring")
                .value_name("FILE")
                .num_args(1)
                .required(true)
                .action(ArgAction::Append)
                .help("take the keys from the keyring FILE"),
        )
        .arg(
            Arg::new("FILES")
                .required(true)
                .num_args(1)
                .action(ArgAction::Append)
                .index(1)
                .help("files to verify"),
        )
        .get_matches();

    let mut keyring = gpgrv::Keyring::new();
    for path in matches.get_raw("keyring").expect("required arg") {
        keyring
            .append_keys_from(
                fs::File::open(path).with_context(|| anyhow!("opening keyring {:?}", path))?,
            )
            .with_context(|| format!("reading keyring {:?}", path))?;
    }

    for &key in keyring.key_ids() {
        println!("loaded key: {:016x}", key);
    }

    for file in matches.get_raw("FILES").expect("required arg") {
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
