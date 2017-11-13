extern crate clap;
extern crate gpgrv;

use std::fs;
use std::io;

use clap::App;
use clap::Arg;

fn main() {
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
            .append_keys_from(fs::File::open(path).expect("can't open keyring"))
            .expect("can't open keyring");
    }

    for file in matches.values_of_os("FILES").unwrap() {
        gpgrv::verify_clearsign_armour(
            io::BufReader::new(fs::File::open(file).expect("can't open input file")),
            &keyring,
        ).expect("verification problem");
    }
}
