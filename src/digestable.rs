use digest::Input;
use digest::FixedOutput;

pub enum Digestable {
    Sha1(::sha_1::Sha1),
    Sha256(::sha2::Sha256),
    Sha512(::sha2::Sha512),
}

impl Digestable {
    // Like digest::Input
    pub fn process(&mut self, data: &[u8]) {
        use self::Digestable::*;
        match self {
            &mut Sha1(mut x) => x.process(data),
            &mut Sha256(mut x) => x.process(data),
            &mut Sha512(mut x) => x.process(data),
        }
    }
}

impl Input for Digestable {
    fn process(&mut self, data: &[u8]) {
        Self::process(self, data)
    }
}
