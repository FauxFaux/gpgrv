use std::io;

use anyhow::Result;

#[test]
fn free_bsd() -> Result<()> {
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

#[test]
fn debian_2023() -> Result<()> {
    let mut keyring = gpgrv::Keyring::new();
    keyring.append_keys_from(io::Cursor::new(include_bytes!(
        "deb/2023.09.24/keyring.gpg"
    )))?;
    Ok(())
}
