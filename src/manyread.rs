use std::io;
use std::io::Read;

pub struct ManyReader<R> {
    inner: R,
    data: Vec<u8>,
}

impl<R: Read> ManyReader<R> {
    pub fn new(inner: R) -> ManyReader<R> {
        ManyReader {
            inner,
            data: Vec::new(),
        }
    }

    pub fn fill_many(&mut self, target: usize) -> Result<&[u8], io::Error> {
        while self.data.len() < target {
            let mut buf = [0u8; 8 * 1024];
            let read = self.inner.read(&mut buf)?;
            if 0 == read {
                break;
            }
            self.data.extend(&buf[..read]);
        }

        Ok(&self.data)
    }

    pub fn fill_at_least(&mut self, target: usize) -> Result<&[u8], io::Error> {
        let buf = self.fill_many(target)?;
        if buf.len() < target {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(buf)
    }

    pub fn read_until_limit(&mut self, delim: u8, limit: usize) -> Result<Vec<u8>, io::Error> {
        let buf = self.fill_many(limit)?;
        if let Some(end) = memchr::memchr(delim, buf) {
            let ret = buf[..end].to_vec();
            self.consume(end + 1);
            return Ok(ret);
        }

        Err(io::ErrorKind::UnexpectedEof.into())
    }

    pub fn consume(&mut self, amt: usize) {
        assert!(amt <= self.data.len());
        self.data.drain(..amt);
    }
}

impl<R: Read> Read for ManyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let found = self.fill_many(buf.len())?;
        let valid = buf.len().min(found.len());
        buf[..valid].copy_from_slice(&found[..valid]);
        self.consume(valid);
        Ok(valid)
    }
}
