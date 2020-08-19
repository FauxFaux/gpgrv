use std::io::BufRead;

use anyhow::bail;
use anyhow::Error;

pub trait ShortLine {
    fn read_short_line(&mut self) -> Result<Vec<u8>, Error> {
        self.read_line_max(4096)
    }
    fn read_line_max(&mut self, len: usize) -> Result<Vec<u8>, Error>;
}

impl<B: BufRead> ShortLine for B {
    fn read_line_max(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        let mut line = Vec::with_capacity(4096);

        loop {
            let buf = self.fill_buf()?;

            if buf.is_empty() {
                bail!("empty read after: {:?}", String::from_utf8_lossy(&line));
            }

            if let Some(excluding_new_line) = memchr::memchr(b'\n', buf) {
                line.extend_from_slice(&buf[..excluding_new_line]);
                self.consume(excluding_new_line + 1);
                return Ok(line);
            } else {
                if line.len() + buf.len() > len {
                    bail!(
                        "too long, adding {:?} to {:?}",
                        String::from_utf8_lossy(buf),
                        String::from_utf8_lossy(&line)
                    );
                }
                line.extend_from_slice(buf);
                // BORROW CHECKER
                let len = buf.len();
                self.consume(len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::iter;

    use super::ShortLine;

    #[test]
    fn short_line() {
        let mut r = io::Cursor::new(b"foo\nbar\n");
        assert_eq!(b"foo", r.read_short_line().unwrap().as_slice());
        assert_eq!(b"bar", r.read_short_line().unwrap().as_slice());
    }

    #[test]
    fn short_line_evil() {
        let mut r = io::BufReader::new(iowrap::ShortRead::new(
            io::Cursor::new(b"foo\nbar\n"),
            iter::repeat(1),
        ));
        assert_eq!(b"foo", r.read_short_line().unwrap().as_slice());
        assert_eq!(b"bar", r.read_short_line().unwrap().as_slice());
    }
}
