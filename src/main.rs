extern crate byteorder;
extern crate clap;
#[macro_use] extern crate log;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_yaml;
extern crate simple_logger;
extern crate tee; // TODO: switch to io::Read.tee once it is stabilized

use byteorder::{NetworkEndian, ReadBytesExt};
use std::cmp::min;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::net;
use std::ops::Deref;
use std::sync::Arc;
use std::thread;
use std::time;
use tee::TeeReader;

// TODO: use async/await with e.g. Tokio once it is stabilized

fn main() {
    // Initialize, parse & verify flags.
    simple_logger::init().expect("Could not initialize logging");
    let flags = clap::App::new("rspd")
        .version("0.1")
        .author("Brandon Pitman <brandon.pitman@gmail.com>")
        .about("Simple SNI-based HTTPS proxy.")
        .arg(clap::Arg::with_name("config")
             .long("config")
             .value_name("FILE")
             .help("The config file to use")
             .required(true)
             .takes_value(true))
        .get_matches();

    // Read, parse, & verify config.
    let cfg = Arc::new({
        let config_filename = flags.value_of_os("config").unwrap();
        let config_file = File::open(config_filename).expect("Could not open config file");
        serde_yaml::from_reader(config_file).expect("Could not parse config file")
    });

    // Main loop: accept & handle connections.
    let listener = TcpListener::bind("0.0.0.0:443").expect("Could not listen for connections");

    info!("Listening for connections on port {}", listener.local_addr().unwrap().port());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || {
                    let client_addr = stream.peer_addr().unwrap().ip();
                    info!("[{}] Accepted connection", client_addr);
                    match handle_connection(&cfg, stream) {
                        Ok(_) => info!("[{}] Closed connection", client_addr),
                        Err(e) => error!("[{}] Closed connection with error: {}", client_addr, e),
                    };
                });
            }
            Err(e) => error!("Could not accept connection: {}", e),
        }
    }
}

#[derive(Deserialize)]
struct Config {
    host_mappings: HashMap<String, String>,
}

fn handle_connection(cfg: &Config, client_stream: TcpStream) -> io::Result<()> {
    let client_addr = client_stream.peer_addr()?.ip();
    client_stream.set_read_timeout(Some(time::Duration::from_secs(5)))?;
    
    // Read SNI hostname.
    let mut read_buf = Vec::new();
    let sni_host_name = {
        let mut reader = HandshakeRecordReader::new(BufReader::new(TeeReader::new(&client_stream, &mut read_buf)));
        read_sni_host_name_from_handshake_message(&mut reader)?
    };

    // Determine server hostname & dial it.
    let server_host = match cfg.host_mappings.get(&sni_host_name) {
        Some(server_host) => server_host,
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown SNI hostname {}", sni_host_name))),
    };
    info!("[{}] Sent SNI hostname {}, mapping to {}", client_addr, sni_host_name, server_host);
    let server_stream = Arc::new(TcpStream::connect(format!("{}:443", server_host))?);

    // Copy data between client & server.
    client_stream.set_read_timeout(None)?; // at this point, trust the timeouts of the server
    let client_stream = Arc::new(client_stream);
    let client_to_server_handle = {
        let (client_stream, server_stream) = (Arc::clone(&client_stream), Arc::clone(&server_stream));
        thread::spawn(move || {
            //server_stream.deref().write_all(&read_buf)?;
            //io::copy(&mut client_stream.deref(), &mut server_stream.deref())?;
            io::copy(&mut read_buf.chain(client_stream.deref()), &mut server_stream.deref())?;
            // client_stream must be at EOF now. Ignore NotConnected errors on close.
            server_stream.shutdown(net::Shutdown::Write).or_else(|err| {
                match err.kind() {
                    io::ErrorKind::NotConnected => Ok(()),
                    _ => Err(err),
                }
            })
        })
    };
    let server_to_client_handle = {
        let (client_stream, server_stream) = (Arc::clone(&client_stream), Arc::clone(&server_stream));
        thread::spawn(move || {
            io::copy(&mut server_stream.deref(), &mut client_stream.deref())?;
            // server_stream must be at EOF now. Ignore NotConnected errors on close.
            client_stream.shutdown(net::Shutdown::Write).or_else(|err| {
                match err.kind() {
                    io::ErrorKind::NotConnected => Ok(()),
                    _ => Err(err),
                }
            })
        })
    };

    let client_to_server_rslt = client_to_server_handle.join().unwrap();
    let server_to_client_rslt = server_to_client_handle.join().unwrap();
    client_to_server_rslt.and(server_to_client_rslt)
}

struct HandshakeRecordReader<R: Read>(Option<InternalHandshakeRecordReader<R>>);

impl<R: Read> HandshakeRecordReader<R> {
    fn new(reader: R) -> HandshakeRecordReader<R> {
        HandshakeRecordReader(Some(InternalHandshakeRecordReader::new(reader)))
    }
}

impl<R: Read> Read for HandshakeRecordReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rslt = self.0.as_mut().expect("Read from already-errored HandshakeRecordReader").read(buf);
        if rslt.is_err() {
            self.0 = None
        }
        rslt
    }
}

struct InternalHandshakeRecordReader<R: Read> {
    reader: R,
    rec_len: usize,
}

impl<R: Read> InternalHandshakeRecordReader<R> {
    fn new(reader: R) -> InternalHandshakeRecordReader<R> {
        InternalHandshakeRecordReader {
            reader: reader,
            rec_len: 0,
        }
    }
}

impl<R: Read> Read for InternalHandshakeRecordReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rec_len == 0 {
            // Read record header to figure out how much record data we can read.

            // Content-type.
            const CONTENT_TYPE_HANDSHAKE: u8 = 22;
            let content_type = self.reader.read_u8()?;
            if content_type != CONTENT_TYPE_HANDSHAKE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("got wrong content type (wanted {}, got {})", CONTENT_TYPE_HANDSHAKE, content_type)));
            }

            // Major & minor version.
            self.reader.read_u16::<NetworkEndian>()?;

            // Read record data length.
            const MAX_RECORD_SIZE: usize = 1 << 14;
            self.rec_len = self.reader.read_u16::<NetworkEndian>()?.into();
            if self.rec_len > MAX_RECORD_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("record too large ({} > {})", self.rec_len, MAX_RECORD_SIZE)));
            }
        }

        // Read up to the remainder of the current record into the provided buffer.
        let read_len = min(self.rec_len, buf.len());
        let buf = &mut buf[..read_len];
        self.reader.read(buf).and_then(|sz| {
            self.rec_len -= sz;
            Ok(sz)
        })
    }
}

fn read_sni_host_name_from_handshake_message<R: Read>(reader: &mut R) -> io::Result<String> {
    // Handshake message type.
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    let typ = reader.read_u8()?;
    if typ != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("handshake message not a ClientHello (type {}, expected {})", typ, HANDSHAKE_TYPE_CLIENT_HELLO)));
    }

    // Handshake message length.
    let len = reader.read_u24::<NetworkEndian>()?;
    let mut reader = reader.take(len.into());

    // ProtocolVersion (2 bytes) & random (32 bytes).
    skip(&mut reader, 34)?;

    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    skip_vec_u8(&mut reader)?;
    skip_vec_u16(&mut reader)?;
    skip_vec_u8(&mut reader)?;

    // Extensions.
    let ext_len = reader.read_u16::<NetworkEndian>()?;
    let mut reader = reader.take(ext_len.into());
    loop {
        // Extension type & length.
        let ext_typ = reader.read_u16::<NetworkEndian>()?;
        let ext_len = reader.read_u16::<NetworkEndian>()?;

        const EXTENSION_TYPE_SNI: u16 = 0;
        if ext_typ != EXTENSION_TYPE_SNI {
            skip(&mut reader, ext_len.into())?;
            continue;
        }
        let mut reader = reader.take(ext_len.into());

        // ServerNameList length.
        let snl_len = reader.read_u16::<NetworkEndian>()?;
        let mut reader = reader.take(snl_len.into());

        // ServerNameList.
        loop {
            // NameType & length.
            let name_typ = reader.read_u8()?;

            const NAME_TYPE_HOST_NAME: u8 = 0;
            if name_typ != NAME_TYPE_HOST_NAME {
                skip_vec_u16(&mut reader)?;
                continue;
            }

            let name_len = reader.read_u16::<NetworkEndian>()?;
            let mut name_buf = vec![0; name_len.into()];
            reader.read_exact(&mut name_buf)?;
            return match String::from_utf8(name_buf) {
                Ok(s) => Ok(s),
                Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }
    }
}

fn skip<R: Read>(reader: &mut R, len: u64) -> io::Result<()> {
    io::copy(&mut reader.take(len), &mut io::sink()).and_then(|_| Ok(()))
}

fn skip_vec_u8<R: Read>(reader: &mut R) -> io::Result<()> {
    let sz = reader.read_u8()?;
    skip(reader, sz.into())
}

fn skip_vec_u16<R: Read>(reader: &mut R) -> io::Result<()> {
    let sz = reader.read_u16::<NetworkEndian>()?;
    skip(reader, sz.into())
}
