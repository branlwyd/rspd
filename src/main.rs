extern crate async_std;
extern crate byteorder;
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate pin_project;
#[macro_use]
extern crate pin_utils;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate simple_logger;

use async_std::prelude::*;

use async_std::io;
use async_std::io::{Error, Read};
use async_std::net::{TcpListener, TcpStream};
use async_std::task;
use byteorder::{ByteOrder, NetworkEndian};
use log::Level;
use std::cmp::min;
use std::collections::HashMap;
use std::fs::File;
use std::net;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

// TODO: re-implement HandshakeRecordReader in a saner way and nuke the existing implementation from orbit
// TODO: implement read_u{8,16,24} as an extension trait on Read once async traits functions are supported

fn main() {
    // Initialize, parse & verify flags.
    simple_logger::init_with_level(Level::Info).expect("Couldn't initialize logging");
    let flags = clap::App::new("rspd")
        .version("1.0.0")
        .author("Brandon Pitman <bran@bran.land>")
        .about("Simple SNI-based HTTPS proxy.")
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .value_name("FILE")
                .help("The config file to use")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    // Read, parse, & verify config.
    let cfg = Arc::new({
        let config_filename = flags.value_of_os("config").unwrap();
        let config_file = File::open(config_filename).expect("Couldn't open config file");
        serde_yaml::from_reader(config_file).expect("Couldn't parse config file")
    });

    // Main loop: accept & handle connections.
    task::block_on(async {
        let listener = TcpListener::bind("0.0.0.0:443")
            .await
            .expect("Couldn't listen for connections");
        let mut incoming = listener.incoming();

        info!(
            "Listening for connections on port {}",
            listener.local_addr().unwrap().port()
        );

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    let cfg = Arc::clone(&cfg);
                    task::spawn(async move {
                        let client_addr = match stream.peer_addr() {
                            Ok(peer_addr) => peer_addr.ip(),
                            Err(err) if err.kind() == io::ErrorKind::NotConnected => return, // silently ignore clients that quickly close connection
                            Err(err) => {
                                error!("Couldn't get client address: {}", err);
                                return;
                            }
                        };

                        info!("[{}] Accepted connection", client_addr);
                        match handle_connection(&cfg, stream).await {
                            Ok(_) => info!("[{}] Closed connection", client_addr),
                            Err(err) => {
                                error!("[{}] Closed connection with error: {}", client_addr, err)
                            }
                        }
                    });
                }
                Err(err) => error!("Couldn't accept connection: {}", err),
            }
        }
    });
}

#[derive(Deserialize)]
struct Config {
    host_mappings: HashMap<String, String>,
}

async fn handle_connection(cfg: &Config, client_stream: TcpStream) -> io::Result<()> {
    let client_addr = client_stream.peer_addr()?.ip();
    // Read SNI hostname.
    let (sni_hostname, read_buf) = {
        let mut recording_reader = RecordingReader::new(&client_stream);
        let reader = HandshakeRecordReader::new(&mut recording_reader);
        pin_mut!(reader);
        let hostname = io::timeout(
            Duration::from_secs(5),
            read_sni_host_name_from_client_hello(reader),
        )
        .await?;
        (hostname, recording_reader.buf())
    };

    // Determine server hostname & dial it.
    let server_host = match cfg.host_mappings.get(&sni_hostname) {
        Some(server_host) => server_host,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown SNI hostname {}", sni_hostname),
            ))
        }
    };
    info!(
        "[{}] Sent SNI hostname {}, mapping to {}",
        client_addr, sni_hostname, server_host
    );
    let client_stream = Arc::new(client_stream);
    let server_stream = Arc::new(TcpStream::connect(format!("{}:443", server_host)).await?);

    // Copy data between client & server.
    let client_to_server_handle = {
        let (client_stream, server_stream) =
            (Arc::clone(&client_stream), Arc::clone(&server_stream));
        task::spawn(async move {
            io::copy(
                &mut read_buf.chain(client_stream.deref()),
                &mut server_stream.deref(),
            )
            .await?;
            // client_stream must be at EOF now. Ignore NotConnected errors on close.
            server_stream
                .shutdown(net::Shutdown::Write)
                .or_else(|err| match err.kind() {
                    io::ErrorKind::NotConnected => Ok(()),
                    _ => Err(err),
                })
        })
    };
    async move {
        io::copy(&mut server_stream.deref(), &mut client_stream.deref()).await?;
        // server_stream must be at EOF now. Ignore NotConnected errors on close.
        client_stream
            .shutdown(net::Shutdown::Write)
            .or_else(|err| match err.kind() {
                io::ErrorKind::NotConnected => Ok(()),
                _ => Err(err),
            })
    }
    .await
    .and(client_to_server_handle.await)
}

#[pin_project]
struct RecordingReader<R: Read> {
    #[pin]
    reader: R,
    buf: Vec<u8>,
}

impl<R: Read> RecordingReader<R> {
    fn new(reader: R) -> RecordingReader<R> {
        RecordingReader {
            reader: reader,
            buf: Vec::new(),
        }
    }

    fn buf(self: Self) -> Vec<u8> {
        self.buf
    }
}

impl<R: Read> Read for RecordingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let mut this = self.project();
        let rslt = this.reader.as_mut().poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = rslt {
            this.buf.extend(&buf[..n]);
        }
        rslt
    }
}

#[pin_project]
struct HandshakeRecordReader<R: Read> {
    #[pin]
    reader: R,
    state: HandshakeRecordReaderState,
}

impl<R: Read> HandshakeRecordReader<R> {
    fn new(reader: R) -> HandshakeRecordReader<R> {
        HandshakeRecordReader {
            reader: reader,
            state: HandshakeRecordReaderState::ReadingContentType,
        }
    }
}

enum HandshakeRecordReaderState {
    ReadingContentType,
    ReadingMajorMinorVersion(usize),
    ReadingRecordSize([u8; 2], usize),
    ReadingRecord(usize),
}

impl<R: Read> Read for HandshakeRecordReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let mut this = self.project();
        loop {
            match this.state {
                HandshakeRecordReaderState::ReadingContentType => {
                    const CONTENT_TYPE_HANDSHAKE: u8 = 22;
                    let mut buf: [u8; 1] = [0];
                    match this.reader.as_mut().poll_read(cx, &mut buf[..]) {
                        Poll::Ready(Ok(1)) => {
                            if buf[0] != CONTENT_TYPE_HANDSHAKE {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "got wrong content type (wanted {}, got {})",
                                        CONTENT_TYPE_HANDSHAKE, buf[0]
                                    ),
                                )));
                            }
                            *this.state = HandshakeRecordReaderState::ReadingMajorMinorVersion(2);
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderState::ReadingMajorMinorVersion(bytes_remaining) => {
                    let mut buf: [u8; 2] = [0; 2];
                    match this.reader.as_mut().poll_read(cx, &mut buf[..]) {
                        Poll::Ready(Ok(n)) => {
                            *bytes_remaining -= n;
                            if *bytes_remaining == 0 {
                                *this.state =
                                    HandshakeRecordReaderState::ReadingRecordSize([0; 2], 2);
                            }
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderState::ReadingRecordSize(buf, bytes_remaining) => {
                    const MAX_RECORD_SIZE: usize = 1 << 14;
                    match this
                        .reader
                        .as_mut()
                        .poll_read(cx, &mut buf[2 - *bytes_remaining..])
                    {
                        Poll::Ready(Ok(n)) => {
                            *bytes_remaining -= n;
                            if *bytes_remaining == 0 {
                                let record_size: usize = NetworkEndian::read_u16(buf).into();
                                if record_size > MAX_RECORD_SIZE {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "record too large ({} > {})",
                                            record_size, MAX_RECORD_SIZE
                                        ),
                                    )));
                                }
                                *this.state = HandshakeRecordReaderState::ReadingRecord(record_size)
                            }
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderState::ReadingRecord(record_size) => {
                    let read_len = min(*record_size, buf.len());
                    let buf = &mut buf[..read_len];
                    let rslt = this.reader.as_mut().poll_read(cx, buf);
                    if let Poll::Ready(Ok(n)) = rslt {
                        *record_size -= n;
                        if *record_size == 0 {
                            *this.state = HandshakeRecordReaderState::ReadingContentType;
                        }
                    }
                    return rslt;
                }
            }
        }
    }
}

async fn read_sni_host_name_from_client_hello<R: Read>(
    mut reader: Pin<&mut R>,
) -> io::Result<String> {
    // Handshake message type.
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    let typ = read_u8(reader.as_mut()).await?;
    if typ != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "handshake message not a ClientHello (type {}, expected {})",
                typ, HANDSHAKE_TYPE_CLIENT_HELLO
            ),
        ));
    }

    // Handshake message length.
    let len = read_u24(reader.as_mut()).await?;
    let reader = reader.take(len.into());
    pin_mut!(reader);

    // ProtocolVersion (2 bytes) & random (32 bytes).
    skip(reader.as_mut(), 34).await?;

    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    skip_vec_u8(reader.as_mut()).await?;
    skip_vec_u16(reader.as_mut()).await?;
    skip_vec_u8(reader.as_mut()).await?;

    // Extensions.
    let ext_len = read_u16(reader.as_mut()).await?;
    let reader = reader.take(ext_len.into());
    pin_mut!(reader);
    loop {
        // Extension type & length.
        let ext_typ = read_u16(reader.as_mut()).await?;
        let ext_len = read_u16(reader.as_mut()).await?;

        const EXTENSION_TYPE_SNI: u16 = 0;
        if ext_typ != EXTENSION_TYPE_SNI {
            skip(reader.as_mut(), ext_len.into()).await?;
            continue;
        }
        let reader = reader.take(ext_len.into());
        pin_mut!(reader);

        // ServerNameList length.
        let snl_len = read_u16(reader.as_mut()).await?;
        let reader = reader.take(snl_len.into());
        pin_mut!(reader);

        // ServerNameList.
        loop {
            // NameType & length.
            let name_typ = read_u8(reader.as_mut()).await?;

            const NAME_TYPE_HOST_NAME: u8 = 0;
            if name_typ != NAME_TYPE_HOST_NAME {
                skip_vec_u16(reader.as_mut()).await?;
                continue;
            }

            let name_len = read_u16(reader.as_mut()).await?;
            let mut name_buf = vec![0; name_len.into()];
            reader.read_exact(&mut name_buf).await?;
            return match String::from_utf8(name_buf) {
                Ok(s) => Ok(s),
                Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            };
        }
    }
}

async fn skip<R: Read>(reader: Pin<&mut R>, len: u64) -> io::Result<()> {
    io::copy(&mut reader.take(len), &mut io::sink()).await?;
    Ok(())
}

async fn skip_vec_u8<R: Read>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = read_u8(reader.as_mut()).await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn skip_vec_u16<R: Read>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = read_u16(reader.as_mut()).await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn read_u8<R: Read>(mut reader: Pin<&mut R>) -> io::Result<u8> {
    let mut buf = [0; 1];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16<R: Read>(mut reader: Pin<&mut R>) -> io::Result<u16> {
    let mut buf = [0; 2];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(NetworkEndian::read_u16(&buf))
}

async fn read_u24<R: Read>(mut reader: Pin<&mut R>) -> io::Result<u32> {
    let mut buf = [0; 3];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(NetworkEndian::read_u24(&buf))
}
