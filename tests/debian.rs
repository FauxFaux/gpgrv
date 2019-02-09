use std::io;

use failure::Error;

#[test]
fn free_bsd() -> Result<(), Error> {
    let mut keyring = gpgrv::Keyring::new();
    keyring.append_keys_from(io::Cursor::new(distro_keyring::supported_debian_keys()))?;

    let mut out = Vec::new();
    gpgrv::verify_message(
        io::Cursor::new(&include_bytes!("deb/jessie-kfreebsd/InRelease")[..]),
        &mut out,
        &keyring,
    )
    .unwrap();

    Ok(())
}
