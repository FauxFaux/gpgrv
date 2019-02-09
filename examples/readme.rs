use std::io::{stdin, stdout, BufReader, Cursor, Seek, SeekFrom};
fn main() {
    // load a keyring from some file(s)
    // for example, we use the linux distribution keyring
    let mut keyring = gpgrv::Keyring::new();
    let keyring_file = Cursor::new(distro_keyring::supported_keys());
    keyring.append_keys_from(keyring_file).unwrap();

    // read stdin, verify, and write the output to a temporary file
    let mut temp = tempfile::tempfile().unwrap();
    gpgrv::verify_message(BufReader::new(stdin()), &mut temp, &keyring).expect("verification");

    // if we succeeded, print the temporary file to stdout
    temp.seek(SeekFrom::Start(0)).unwrap();
    std::io::copy(&mut temp, &mut stdout()).unwrap();
}
