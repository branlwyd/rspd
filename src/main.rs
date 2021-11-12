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
extern crate tokio;

use byteorder::{ByteOrder, NetworkEndian};
use log::Level;
use std::cmp::min;
use std::collections::HashMap;
use std::fs::File;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, BufReader, Error, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use tokio::time;

// TODO: re-implement HandshakeRecordReader in a saner way and nuke the existing implementation from orbit
// TODO: implement read_u{8,16,24} as an extension trait on Read once async traits functions are supported

#[tokio::main]
async fn main() {
    // Initialize, parse & verify flags.
    simple_logger::init_with_level(Level::Info).expect("Couldn't initialize logging");
    let flags = clap::App::new("rspd")
        .version(env!("CARGO_PKG_VERSION"))
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
    let cfg: &'static Config = Box::leak(Box::new({
        let config_filename = flags.value_of_os("config").unwrap();
        let config_file = File::open(config_filename).expect("Couldn't open config file");
        serde_yaml::from_reader(config_file).expect("Couldn't parse config file")
    }));

    // Main loop: accept & handle connections.
    #[cfg(not(debug_assertions))]
    const LISTEN_PORT: u16 = 443;
    #[cfg(debug_assertions)]
    const LISTEN_PORT: u16 = 10443;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, LISTEN_PORT))
        .await
        .expect("Couldn't listen for connections");
    info!("Listening for connections on port {}", LISTEN_PORT);

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                task::spawn(async move {
                    info!("[{}] Accepted connection", client_addr);
                    match handle_connection(cfg, client_addr, stream).await {
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
}

#[derive(Deserialize)]
struct Config {
    host_mappings: HashMap<String, String>,
}

async fn handle_connection(
    cfg: &Config,
    client_addr: SocketAddr,
    mut client_stream: TcpStream,
) -> io::Result<()> {
    // Read SNI hostname.
    let mut recording_reader = RecordingReader::new(&mut client_stream);
    let reader = HandshakeRecordReader::new(BufReader::new(&mut recording_reader));
    pin_mut!(reader);
    let sni_hostname = time::timeout(
        Duration::from_secs(5),
        read_sni_host_name_from_client_hello(reader),
    )
    .await??;
    let read_buf = recording_reader.buf();

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

    let mut client_stream = PrefixedReaderWriter::new(client_stream, read_buf);
    let mut server_stream = TcpStream::connect((&server_host[..], 443)).await?;
    io::copy_bidirectional(&mut client_stream, &mut server_stream).await?;
    Ok(())
}

#[pin_project]
struct RecordingReader<R: AsyncRead> {
    #[pin]
    reader: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead> RecordingReader<R> {
    fn new(reader: R) -> RecordingReader<R> {
        RecordingReader {
            reader,
            buf: Vec::new(),
        }
    }

    fn buf(self) -> Vec<u8> {
        self.buf
    }
}

impl<R: AsyncRead> AsyncRead for RecordingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut this = self.project();
        let n = buf.filled().len();
        let rslt = this.reader.as_mut().poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = rslt {
            let filled = buf.filled();
            this.buf.extend(&filled[n..]);
        }
        rslt
    }
}

#[pin_project]
struct PrefixedReaderWriter<T: AsyncRead + AsyncWrite> {
    #[pin]
    inner: T,
    prefix: Vec<u8>,
    read_prefix: usize,
}

impl<'a, T: AsyncRead + AsyncWrite> PrefixedReaderWriter<T> {
    fn new(inner: T, prefix: Vec<u8>) -> PrefixedReaderWriter<T> {
        PrefixedReaderWriter {
            inner,
            prefix,
            read_prefix: 0,
        }
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for PrefixedReaderWriter<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        if this.prefix.is_empty() {
            return this.inner.poll_read(cx, buf);
        }

        let read_prefix = *this.read_prefix;
        let prefix = &this.prefix[read_prefix..];
        let read_size = min(buf.remaining(), prefix.len());
        buf.put_slice(&prefix[..read_size]);
        *this.read_prefix += read_size;

        if *this.read_prefix == this.prefix.len() {
            mem::take(this.prefix);
        }

        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for PrefixedReaderWriter<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        this.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();
        this.inner.poll_shutdown(cx)
    }
}

#[pin_project]
struct HandshakeRecordReader<R: AsyncRead> {
    #[pin]
    reader: R,
    currently_reading: HandshakeRecordReaderReading,
}

impl<R: AsyncRead> HandshakeRecordReader<R> {
    fn new(reader: R) -> HandshakeRecordReader<R> {
        HandshakeRecordReader {
            reader,
            currently_reading: HandshakeRecordReaderReading::ContentType,
        }
    }
}

enum HandshakeRecordReaderReading {
    ContentType,
    MajorMinorVersion(usize),
    RecordSize([u8; 2], usize),
    Record(usize),
}

impl<R: AsyncRead> AsyncRead for HandshakeRecordReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        caller_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        let mut this = self.project();
        loop {
            match this.currently_reading {
                HandshakeRecordReaderReading::ContentType => {
                    const CONTENT_TYPE_HANDSHAKE: u8 = 22;
                    let mut buf = [0];
                    let mut buf = ReadBuf::new(&mut buf[..]);
                    match this.reader.as_mut().poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) if buf.filled().len() == 1 => {
                            if buf.filled()[0] != CONTENT_TYPE_HANDSHAKE {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "got wrong content type (wanted {}, got {})",
                                        CONTENT_TYPE_HANDSHAKE,
                                        buf.filled()[0]
                                    ),
                                )));
                            }
                            *this.currently_reading =
                                HandshakeRecordReaderReading::MajorMinorVersion(0);
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderReading::MajorMinorVersion(bytes_read) => {
                    let mut buf = [0, 0];
                    let mut buf = ReadBuf::new(&mut buf[..]);
                    buf.advance(*bytes_read);
                    match this.reader.as_mut().poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) => {
                            *bytes_read = buf.filled().len();
                            if *bytes_read == 2 {
                                *this.currently_reading =
                                    HandshakeRecordReaderReading::RecordSize([0, 0], 0);
                            }
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderReading::RecordSize(buf, bytes_read) => {
                    const MAX_RECORD_SIZE: usize = 1 << 14;
                    let mut buf = ReadBuf::new(&mut buf[..]);
                    buf.advance(*bytes_read);
                    match this.reader.as_mut().poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) => {
                            *bytes_read = buf.filled().len();
                            if *bytes_read == 2 {
                                let record_size: usize =
                                    NetworkEndian::read_u16(buf.filled()).into();
                                if record_size > MAX_RECORD_SIZE {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "record too large ({} > {})",
                                            record_size, MAX_RECORD_SIZE
                                        ),
                                    )));
                                }
                                *this.currently_reading =
                                    HandshakeRecordReaderReading::Record(record_size)
                            }
                        }
                        rslt => return rslt,
                    }
                }

                HandshakeRecordReaderReading::Record(remaining_record_bytes) => {
                    // This is gross: we want to read into caller_buf, BUT calling `take` gives a
                    // ReadBuf that has the same underlying buffer but an independent filled
                    // cursor. So we have to call `advance` manually, BUT to avoid panics we also
                    // have to call `initialize_unfilled_to` to ensure we don't advance into
                    // uninitialized memory.
                    //
                    // This is a terribly-designed API. A better API would have caused `take` to
                    // return a "view" that updated the "filled" cursor of the covered ReadBuf,
                    // too, rather than requiring every single user of the API to figure out that
                    // this is required and implement it every time they want a limited read.

                    caller_buf.initialize_unfilled_to(min(
                        caller_buf.remaining(),
                        *remaining_record_bytes,
                    ));
                    let mut buf = caller_buf.take(*remaining_record_bytes);
                    let old_bytes_read = buf.filled().len();
                    let rslt = this.reader.as_mut().poll_read(cx, &mut buf);
                    if let Poll::Ready(Ok(())) = rslt {
                        let bytes_read = buf.filled().len() - old_bytes_read;
                        caller_buf.advance(bytes_read);
                        *remaining_record_bytes -= bytes_read;
                        if *remaining_record_bytes == 0 {
                            *this.currently_reading = HandshakeRecordReaderReading::ContentType;
                        }
                    }
                    return rslt;
                }
            }
        }
    }
}

async fn read_sni_host_name_from_client_hello<R: AsyncRead>(
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

async fn skip<R: AsyncRead>(reader: Pin<&mut R>, len: u64) -> io::Result<()> {
    io::copy(&mut reader.take(len), &mut io::sink()).await?;
    Ok(())
}

async fn skip_vec_u8<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = read_u8(reader.as_mut()).await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn skip_vec_u16<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = read_u16(reader.as_mut()).await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn read_u8<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<u8> {
    let mut buf = [0; 1];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<u16> {
    let mut buf = [0; 2];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(NetworkEndian::read_u16(&buf))
}

async fn read_u24<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<u32> {
    let mut buf = [0; 3];
    reader.as_mut().read_exact(&mut buf).await?;
    Ok(NetworkEndian::read_u24(&buf))
}
