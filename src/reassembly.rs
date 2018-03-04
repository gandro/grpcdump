use std::io::{self, Cursor};
use std::io::prelude::*;
use futures::{Async, Poll};
use tokio_io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
pub struct TcpStream {
    stream: Cursor<Vec<u8>>,
}

impl TcpStream {
    pub fn new() -> Self {
        TcpStream {
            stream: Cursor::new(Vec::new()),
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.stream.get_mut().extend_from_slice(bytes);
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl AsyncRead for TcpStream {}

impl Write for TcpStream {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("tried to write: {:?}", buf);
        Ok(buf.len())
    }
    #[inline]
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsyncWrite for TcpStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        println!("shutdown requested");
        Ok(Async::Ready(()))
    }
}
