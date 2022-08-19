use std::io::Read as StreamRead;
use std::io::Write as StreamWrite;
use std::net::TcpStream;

use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use puny_tls::Session;
use rand_core::OsRng;

pub fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let host = if args.len() > 1 {
        args[1].to_string()
    } else {
        "www.google.com".to_string()
    };
    let port = if args.len() > 2 {
        args[2].to_string()
    } else {
        "443".to_string()
    };

    let stream = std::net::TcpStream::connect(format!("{host}:{port}")).unwrap();
    let io = InputOutput(stream);
    let mut rng = OsRng;
    let mut tls: Session<'_, InputOutput, 8096> = Session::new(io, host.as_str(), &mut rng);

    tls.write(format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
        .unwrap();
    loop {
        let mut buf = [0u8; 512];
        match tls.read(&mut buf) {
            Ok(len) => {
                let text: String = buf[..len].iter().map(|&c| c as char).collect();
                println!("{}", text);
            }
            Err(err) => {
                println!("Got error: {:?}", err);
                break;
            }
        }
    }
}

struct InputOutput(TcpStream);

#[derive(Debug)]
enum IoError {
    Other,
}

impl embedded_io::Error for IoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl Io for InputOutput {
    type Error = IoError;
}

impl Read for InputOutput {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf).map_err(|_| IoError::Other)
    }
}

impl Write for InputOutput {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        log::info!("write {} bytes", buf.len());

        self.0.write(buf).map_err(|_| IoError::Other)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush().map_err(|_| IoError::Other)
    }
}
