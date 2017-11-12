use digest::Digest;
use digest::Input;
use digest::FixedOutput;

pub enum Digestable {
    Sha1(::sha_1::Sha1),
    Sha256(::sha2::Sha256),
    Sha512(::sha2::Sha512),
}

impl Digestable {
    pub fn input(&mut self) -> &mut Input {
        use self::Digestable::*;
        match *self {
            Sha1(ref mut x) => x,
            Sha256(ref mut x) => x,
            Sha512(ref mut x) => x,
        }
    }

    // Like digest::Input
    pub fn process(&mut self, data: &[u8]) {
        self.input().process(data)
    }

    pub fn hash(&self) -> Vec<u8> {
        use self::Digestable::*;
        match *self {
            Sha1(x) => x.hash().to_vec(),
            Sha256(x) => x.fixed_result().to_vec(),
            Sha512(x) => x.fixed_result().to_vec(),
        }
    }
}
