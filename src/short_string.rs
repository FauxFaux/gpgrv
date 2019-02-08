use std::io;
use std::io::BufRead;

pub trait ShortLine {
    fn read_short_line(&mut self) -> Result<Vec<u8>, io::Error> {
        self.read_line_max(4096)
    }
    fn read_line_max(&mut self, len: usize) -> Result<Vec<u8>, io::Error>;
}

impl<B: BufRead> ShortLine for B {
    fn read_line_max(&mut self, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut line = Vec::with_capacity(4096);

        loop {
            let buf = self.fill_buf()?;

            if buf.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }

            if let Some(excluding_new_line) = memchr::memchr(b'\n', buf) {
                line.extend_from_slice(&buf[..excluding_new_line]);
                self.consume(excluding_new_line + 1);
                return Ok(line);
            } else {
                if line.len() + buf.len() > len {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                line.extend_from_slice(buf);
            }
        }
    }
}

#[test]
fn short_line() {
    let mut r = io::Cursor::new(b"foo\nbar\n");
    assert_eq!(b"foo", r.read_short_line().unwrap().as_slice());
    assert_eq!(b"bar", r.read_short_line().unwrap().as_slice());
}
