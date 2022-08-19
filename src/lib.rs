#![no_std]

use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use buffer::Buffer;
use embedded_io::blocking::{Read, Write};
use embedded_io::Io;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};

use sha2::Digest;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

pub mod buffer;

const MAX_RECORD_SIZE: usize = 16 * 1024 + 40;
const MAX_SUPPORT_SEND_RECORD_SIZE: usize = 4 * 1024 + 40;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsError {
    ReceivedUnexpectedData,
    IoError,
    DataExhausted,
    ConnectionClosed,
}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

struct HandshakeData<const HANDSHAKE_BUFFER_SIZE: usize> {
    _server_random: Option<[u8; 32]>,
    server_public_key: Option<[u8; 32]>,
    client_hello: Option<Buffer<256>>,
    server_hello: Option<Buffer<128>>,
    client_handshake_key: Option<Buffer<16>>,
    server_handshake_key: Option<Buffer<16>>,
    client_handshake_iv: Option<Buffer<12>>,
    server_handshake_iv: Option<Buffer<12>>,
    server_handshake: Option<Buffer<HANDSHAKE_BUFFER_SIZE>>,
    handshake_secret: Option<Buffer<32>>,
    client_handshake_secret: Option<Buffer<32>>,
}

pub struct Session<'a, T, const HANDSHAKE_BUFFER_SIZE: usize>
where
    T: Read + Write,
{
    stream: T,
    servername: &'a str,
    secret: StaticSecret,
    random: [u8; 32],
    client_application_key: Option<Buffer<16>>,
    server_application_key: Option<Buffer<16>>,
    client_application_iv: Option<Buffer<12>>,
    server_application_iv: Option<Buffer<12>>,
    records_received: u64,
    records_sent: u64,
    connected: bool,
    current_data: Option<Buffer<MAX_RECORD_SIZE>>,
    defered_error: Option<TlsError>,
}

impl<'a, T, const HANDSHAKE_BUFFER_SIZE: usize> Session<'a, T, HANDSHAKE_BUFFER_SIZE>
where
    T: Read + Write,
{
    pub fn new<RNG>(
        stream: T,
        servername: &'a str,
        rng: &mut RNG,
    ) -> Session<'a, T, HANDSHAKE_BUFFER_SIZE>
    where
        RNG: CryptoRng + RngCore + rand_core::CryptoRng,
    {
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let secret = StaticSecret::new(rng);

        Session {
            stream,
            servername,
            secret,
            random,
            client_application_key: None,
            server_application_key: None,
            client_application_iv: None,
            server_application_iv: None,
            records_received: 0,
            records_sent: 0,
            connected: false,
            current_data: None,
            defered_error: None,
        }
    }

    #[cfg(test)]
    fn new_test(
        stream: T,
        servername: &'a str,
        random: [u8; 32],
        key: [u8; 32],
    ) -> Session<'a, T, HANDSHAKE_BUFFER_SIZE> {
        let secret = StaticSecret::from(key);

        Session {
            stream,
            servername,
            secret,
            random,
            client_application_key: None,
            server_application_key: None,
            client_application_iv: None,
            server_application_iv: None,
            records_received: 0,
            records_sent: 0,
            connected: false,
            current_data: None,
            defered_error: None,
        }
    }

    fn connect(&mut self) -> Result<(), TlsError> {
        let mut handshake_data: HandshakeData<HANDSHAKE_BUFFER_SIZE> = HandshakeData {
            _server_random: None,
            server_public_key: None,
            client_hello: None,
            server_hello: None,
            client_handshake_key: None,
            server_handshake_key: None,
            client_handshake_iv: None,
            server_handshake_iv: None,
            server_handshake: None,
            handshake_secret: None,
            client_handshake_secret: None,
        };
        self.send_client_hello(&mut handshake_data)?;
        let res = self.process_server_hello(&mut handshake_data);

        res
    }

    #[cfg(test)]
    fn test_process_server_hello(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        self.process_server_hello(handshake_data)
    }

    fn process_server_hello(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        let (_, buffer) = self.read_record_to_buffer()?;
        self.process_server_hello_remaining(buffer, handshake_data)
    }

    fn process_server_hello_remaining(
        &mut self,
        mut buffer: Buffer<128>,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        log::trace!("ServerHello {:02x?}", buffer.slice());

        buffer.read();
        buffer.read();
        buffer.read();
        buffer.read();
        buffer.read();

        // we already skipped over the first 5 bytes
        if buffer.read().ok_or(TlsError::DataExhausted)? != 0x02 {
            // handshake header
            return Err(TlsError::ReceivedUnexpectedData);
        }

        if buffer.read().ok_or(TlsError::DataExhausted)? != 0x00 {
            return Err(TlsError::ReceivedUnexpectedData);
        }

        let _handshake_len = ((buffer.read().ok_or(TlsError::DataExhausted)? as usize) << 8usize)
            | buffer.read().ok_or(TlsError::DataExhausted)? as usize;

        if buffer.read().ok_or(TlsError::DataExhausted)? != 0x03 {
            return Err(TlsError::ReceivedUnexpectedData);
        }
        if buffer.read().ok_or(TlsError::DataExhausted)? != 0x03 {
            return Err(TlsError::ReceivedUnexpectedData);
        }

        let mut server_random = [0u8; 32];
        for i in 0..32 {
            server_random[i] = buffer.read().ok_or(TlsError::DataExhausted)?;
        }

        log::info!("Server random is {:02x?}", &server_random);
        handshake_data.server_public_key = Some(server_random);

        let session_id_len = buffer.read().ok_or(TlsError::DataExhausted)?;
        log::info!("Session ID len is {}", session_id_len);

        for _ in 0..session_id_len {
            buffer.read().ok_or(TlsError::DataExhausted)?; // skip over it
        }

        let cipher_suite_id = ((buffer.read().ok_or(TlsError::DataExhausted)? as usize) << 8usize)
            | buffer.read().ok_or(TlsError::DataExhausted)? as usize;
        log::info!("Chiper Suite ID is {:x}", cipher_suite_id);

        let compression_method = buffer.read().ok_or(TlsError::DataExhausted)?;
        log::info!("Compression method is {}", compression_method);

        // continue with extension_length, parse extensions
        let extensions_len = ((buffer.read().ok_or(TlsError::DataExhausted)? as usize) << 8usize)
            | buffer.read().ok_or(TlsError::DataExhausted)? as usize;
        let mut read_extension_bytes = 0;
        while extensions_len != 0 && read_extension_bytes < extensions_len {
            let extension_id = ((buffer.read().ok_or(TlsError::DataExhausted)? as usize) << 8usize)
                | buffer.read().ok_or(TlsError::DataExhausted)? as usize;
            let extension_len = ((buffer.read().ok_or(TlsError::DataExhausted)? as usize)
                << 8usize)
                | buffer.read().ok_or(TlsError::DataExhausted)? as usize;

            let mut extension_data = Buffer::<128>::new();
            for _ in 0..extension_len {
                extension_data.push_byte(buffer.read().ok_or(TlsError::DataExhausted)?);
            }

            log::trace!(
                "Read extension ID {:x} with {} bytes of data",
                extension_id,
                extension_len
            );

            match extension_id {
                0x0033 => {
                    log::info!("got the server's public key");
                    extension_data.read().ok_or(TlsError::DataExhausted)?; // x25519
                    extension_data.read().ok_or(TlsError::DataExhausted)?; // x25519

                    let key_len = ((extension_data.read().ok_or(TlsError::DataExhausted)?
                        as usize)
                        << 8usize)
                        | extension_data.read().ok_or(TlsError::DataExhausted)? as usize;
                    log::info!("key len is {}", key_len);

                    let mut key = [0u8; 32];
                    key[..].copy_from_slice(extension_data.remaining_slice());
                    handshake_data.server_public_key = Some(key);
                }
                _ => {
                    log::info!("Ignoring extension {:x}", extension_id);
                }
            }

            read_extension_bytes += 2 + 2 + extension_len;
        }
        handshake_data.server_hello = Some(Buffer::new_from_slice(buffer.already_consumed_slice()));

        self.make_handshake_keys(handshake_data);

        // ignore change cipher spec
        let (_, _) = self.read_record_to_buffer::<64>()?;

        self.process_server_handshake(handshake_data)
    }

    fn process_server_handshake(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        let mut all_decrypted = Buffer::new();
        let mut msg_num = 0;

        loop {
            let (_rec_type, contents) = self.read_record_to_buffer()?;
            let mut iv: Buffer<12> = Buffer::new_from_slice(
                handshake_data
                    .server_handshake_iv
                    .as_ref()
                    .ok_or(TlsError::DataExhausted)?
                    .slice(),
            );
            prepare_iv(&mut iv, msg_num);
            let decrypted = decrypt(
                handshake_data
                    .server_handshake_key
                    .as_ref()
                    .ok_or(TlsError::DataExhausted)?,
                &iv,
                &contents,
            );
            all_decrypted.push(decrypted.slice());

            if is_final_handshake_message(decrypted.slice()) {
                break;
            }

            msg_num += 1;
        }

        log::info!("server handshake len {}", all_decrypted.len());
        handshake_data.server_handshake = Some(all_decrypted);
        self.make_application_keys(handshake_data);
        self.client_change_chipher_spec()?;
        self.client_handshake_finished(handshake_data)?;

        log::info!("done with handshake");
        Ok(())
    }

    fn client_handshake_finished(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        let verify_data = self.generate_verify_data(handshake_data);
        let mut msg: Buffer<64> = Buffer::new();
        msg.push(&[0x14, 0x00, 0x00, 0x20]);
        msg.push(verify_data.slice());
        msg.push_byte(0x16);

        let additional = Buffer::new_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x35]);

        let encrypted = encrypt(
            handshake_data
                .client_handshake_key
                .as_ref()
                .ok_or(TlsError::DataExhausted)?,
            handshake_data
                .client_handshake_iv
                .as_ref()
                .ok_or(TlsError::DataExhausted)?,
            &msg,
            &additional,
        );

        log::info!(
            "client handshake finished message {:02x?}",
            encrypted.slice()
        );
        self.stream
            .write(encrypted.slice())
            .map_err(|_| TlsError::IoError)?;
        self.stream.flush().map_err(|_| TlsError::IoError)?;
        Ok(())
    }

    fn generate_verify_data(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Buffer<32> {
        let finished_key = self.hkdf_expand_label::<32>(
            handshake_data
                .client_handshake_secret
                .as_ref()
                .unwrap()
                .slice(),
            b"finished",
            &[],
            32,
        );
        log::trace!("finished_key {:02x?}", finished_key.slice());

        let mut handshake_messages = Buffer::<HANDSHAKE_BUFFER_SIZE>::new();
        handshake_messages.push(&handshake_data.client_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&handshake_data.server_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&handshake_data.server_handshake.as_ref().unwrap().slice());

        let finished_hash = Sha256::digest(handshake_messages.slice());
        log::trace!("finished_hash {:02x?}", finished_hash.as_slice());

        type HmacSha256 = Hmac<Sha256>;

        use hmac::{Hmac, Mac};
        let mut hm = HmacSha256::new_from_slice(finished_key.slice()).unwrap();
        hm.update(finished_hash.as_slice());
        let result = hm.finalize();
        let bytes = result.into_bytes();
        log::trace!("hm {:02x?}", &bytes);

        Buffer::new_from_slice(&bytes)
    }

    fn client_change_chipher_spec(&mut self) -> Result<(), TlsError> {
        self.stream
            .write(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .map_err(|_| TlsError::IoError)?;
        self.stream.flush().map_err(|_| TlsError::IoError)?;
        Ok(())
    }

    fn make_application_keys(&mut self, handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>) {
        let mut handshake_messages = Buffer::<HANDSHAKE_BUFFER_SIZE>::new();
        handshake_messages.push(&handshake_data.client_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&handshake_data.server_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&handshake_data.server_handshake.as_ref().unwrap().slice());

        let zeros = [0u8; 32];
        let derived_secret = self.derive_secret(
            handshake_data.handshake_secret.as_ref().unwrap().slice(),
            b"derived",
            &[],
        );
        log::trace!("app derived secret {:02x?}", derived_secret.slice());
        let (master_secret, _) = Hkdf::<Sha256>::extract(Some(&derived_secret.slice()), &zeros);
        log::trace!("master_secret {:02x?}", master_secret.as_slice());

        let cap_secret = self.derive_secret(
            master_secret.as_slice(),
            b"c ap traffic",
            handshake_messages.slice(),
        );
        log::trace!("cap_secret {:02x?}", cap_secret.slice());
        let client_application_key =
            self.hkdf_expand_label::<16>(cap_secret.slice(), b"key", &[], 16);
        log::trace!(
            "client_application_key {:02x?}",
            client_application_key.slice()
        );
        let client_application_iv =
            self.hkdf_expand_label::<12>(cap_secret.slice(), b"iv", &[], 12);
        log::trace!(
            "client_application_iv {:02x?}",
            client_application_iv.slice()
        );

        let sap_secret = self.derive_secret(
            master_secret.as_slice(),
            b"s ap traffic",
            handshake_messages.slice(),
        );
        log::trace!("master_secret {:02x?}", sap_secret.slice());
        let server_application_key =
            self.hkdf_expand_label::<16>(sap_secret.slice(), b"key", &[], 16);
        log::trace!(
            "server_application_key {:02x?}",
            server_application_key.slice()
        );
        let server_application_iv =
            self.hkdf_expand_label::<12>(sap_secret.slice(), b"iv", &[], 12);
        log::trace!(
            "server_application_iv {:02x?}",
            server_application_iv.slice()
        );

        self.client_application_key = Some(Buffer::new_from_slice(client_application_key.slice()));
        self.client_application_iv = Some(Buffer::new_from_slice(client_application_iv.slice()));
        self.server_application_key = Some(Buffer::new_from_slice(server_application_key.slice()));
        self.server_application_iv = Some(Buffer::new_from_slice(server_application_iv.slice()));
    }

    fn read_record_to_buffer<const LEN: usize>(&mut self) -> Result<(u8, Buffer<LEN>), TlsError> {
        let mut result = Buffer::<LEN>::new();

        let mut record_header = [0u8; 5];
        if self.stream.read(&mut record_header).unwrap() != 5 {
            return Err(TlsError::DataExhausted);
        }

        result.push(&record_header);
        let record_type = record_header[0];
        log::info!("Record type is 0x{:02x}", record_type);
        let len = ((record_header[3] as usize) << 8usize) | record_header[4] as usize;
        log::info!("Record size is {}", len);

        let mut record_content = [0u8; LEN];
        let mut read_count = 0;
        while read_count < len {
            let s = self
                .stream
                .read(&mut record_content[read_count..][..len - read_count])
                .unwrap();
            read_count += s;
        }
        result.push(&record_content[..len]);

        Ok((record_type, result))
    }

    fn make_handshake_keys(&mut self, handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>) {
        // try to calculate the shared secret and make handshake keys
        let server_pk = PublicKey::from(*handshake_data.server_public_key.as_ref().unwrap());
        let client_secret = &self.secret;
        let shared_secret = client_secret.diffie_hellman(&server_pk);
        log::info!("Calculated secret {:02x?}", shared_secret.as_bytes());

        // hkdf extract (hash, secret, salt)
        let zeros = [0u8; 32];
        let psk = [0u8; 32];
        let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&zeros), &psk);
        log::info!("early_secret {:02x?}", early_secret.as_slice());

        let derived_secret = self.derive_secret(early_secret.as_slice(), b"derived", &[]);
        log::info!("derived secret {:02x?}", derived_secret.slice());
        let (handshake_secret, _) =
            Hkdf::<Sha256>::extract(Some(derived_secret.slice()), shared_secret.as_bytes());
        log::info!("handshake_secret {:02x?}", handshake_secret.as_slice());
        handshake_data.handshake_secret = Some(Buffer::new_from_slice(handshake_secret.as_slice()));

        let mut handshake_messages = Buffer::<2048>::new();
        handshake_messages.push(&handshake_data.client_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&handshake_data.server_hello.as_ref().unwrap().slice()[5..]); // strip the record header
        log::info!("handshake_messages {:02x?}", handshake_messages.slice());

        let chs_secret = self.derive_secret(
            handshake_secret.as_slice(),
            b"c hs traffic",
            handshake_messages.slice(),
        );
        log::info!("chs_secret {:02x?}", chs_secret.slice());
        handshake_data.client_handshake_secret = Some(Buffer::new_from_slice(chs_secret.slice()));

        let client_handshake_key =
            self.hkdf_expand_label::<16>(chs_secret.slice(), b"key", &[], 16);
        let client_handshake_iv = self.hkdf_expand_label::<12>(chs_secret.slice(), b"iv", &[], 12);

        log::info!("client_handshake_key {:02x?}", client_handshake_key.slice());
        log::info!("client_handshake_iv {:02x?}", client_handshake_iv.slice());

        handshake_data.client_handshake_key = Some(client_handshake_key);
        handshake_data.client_handshake_iv = Some(client_handshake_iv);

        let shs_secret = self.derive_secret(
            handshake_secret.as_slice(),
            b"s hs traffic",
            handshake_messages.slice(),
        );
        log::info!("shs_secret {:02x?}", chs_secret.slice());

        let server_handshake_key = self.hkdf_expand_label(shs_secret.slice(), b"key", &[], 16);
        let server_handshake_iv = self.hkdf_expand_label(shs_secret.slice(), b"iv", &[], 12);

        handshake_data.server_handshake_key = Some(server_handshake_key);
        handshake_data.server_handshake_iv = Some(server_handshake_iv);
    }

    fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        transcript_messages: &[u8],
    ) -> Buffer<128> {
        let hash = Sha256::digest(transcript_messages);
        self.hkdf_expand_label(secret, label, hash.as_slice(), 32)
    }

    fn hkdf_expand_label<const LEN: usize>(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Buffer<LEN> {
        let mut hkdf_label = Buffer::<LEN>::new();
        hkdf_label.push(&(len as u16).to_be_bytes());
        hkdf_label.push_byte((label.len() + 6) as u8);
        hkdf_label.push(b"tls13 ");
        hkdf_label.push(label);
        hkdf_label.push_byte(context.len() as u8);
        hkdf_label.push(context);

        let mut res_bytes = [0u8; 128];
        let hkdf = Hkdf::<Sha256>::from_prk(secret).unwrap();
        hkdf.expand(hkdf_label.slice(), &mut res_bytes[..len])
            .unwrap();

        Buffer::<LEN>::new_from_slice(&res_bytes[..len])
    }

    fn send_client_hello(
        &mut self,
        handshake_data: &mut HandshakeData<HANDSHAKE_BUFFER_SIZE>,
    ) -> Result<(), TlsError> {
        let mut buffer: Buffer<256> = Buffer::new();

        let mut extensions: Buffer<128> = Buffer::new();
        extensions.push(
            self.extension(0x00, self.server_name(self.servername).slice())
                .slice(),
        );

        extensions.push(self.extension(0x0a, &[0x00, 0x02, 0x00, 0x1d]).slice()); //groups

        // signature algorithms: lots I guess, it doesn't matter because we're not going to verify it
        extensions.push(
            self.extension(
                0x0d,
                &[
                    0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
                    0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
                ],
            )
            .slice(),
        );
        extensions.push(self.extension(0x33, self.public_key().slice()).slice()); // key share
        extensions.push(self.extension(0x2d, &[0x01, 0x01]).slice()); // PSK (no effect)
        extensions.push(self.extension(0x2b, &[0x02, 0x03, 0x04]).slice()); // TLS version
        let mut handshake: Buffer<164> = Buffer::new();
        handshake.push(&[0x03, 0x03]); // client version: TLS 1.2
        handshake.push(&self.random); // 32 bytes of random

        handshake.push(&[0x00]); // no session id
        handshake.push(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: TLS_AES_128_GCM_SHA256
        handshake.push(&[0x01, 0x00]);
        handshake.push(&(extensions.len() as u16).to_be_bytes());
        handshake.push(extensions.slice());

        buffer.push(&[0x16, 0x03, 0x01]); // record header
        buffer.push(&((handshake.len() + 4) as u16).to_be_bytes());
        buffer.push(&[0x01, 0x00]); // handshake
        buffer.push(&(handshake.len() as u16).to_be_bytes());
        buffer.push(handshake.slice());

        log::trace!("Send ClientHello {:02x?}", buffer.slice());

        self.stream
            .write(buffer.slice())
            .map_err(|_| TlsError::IoError)?;
        self.stream.flush().map_err(|_| TlsError::IoError)?;

        handshake_data.client_hello = Some(buffer);

        Ok(())
    }

    fn extension(&self, id: u16, contents: &[u8]) -> Buffer<256> {
        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&id.to_be_bytes());
        buffer.push(&(contents.len() as u16).to_be_bytes());
        buffer.push(contents);

        buffer
    }

    fn server_name(&self, name: &str) -> Buffer<256> {
        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&((name.len() + 3) as u16).to_be_bytes());
        buffer.push_byte(0x00);
        buffer.push(&(name.len() as u16).to_be_bytes());
        buffer.push(name.as_bytes());

        buffer
    }

    fn public_key(&self) -> Buffer<256> {
        let pk = PublicKey::from(&self.secret);
        let public_key = pk.as_bytes();
        log::trace!("PK {:02x?}", public_key);
        log::trace!("PK {}", public_key.len());

        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&((public_key.len() + 4) as u16).to_be_bytes());
        buffer.push(&[0x00, 0x1d]); // x25519
        buffer.push(&(public_key.len() as u16).to_be_bytes());
        buffer.push(public_key);

        buffer
    }

    fn encrypt_application_data<const SIZE: usize>(
        &self,
        iv: Buffer<12>,
        mut data: Buffer<SIZE>,
    ) -> Buffer<SIZE> {
        data.push_byte(0x17);
        let mut additional: Buffer<5> = Buffer::new_from_slice(&[0x17, 0x03, 0x03]);
        additional.push(&((data.len() + 16) as u16).to_be_bytes());
        encrypt(
            self.client_application_key.as_ref().unwrap(),
            &iv,
            &data,
            &additional,
        )
    }

    fn send_data<const SIZE: usize>(&mut self, data: Buffer<SIZE>) -> Result<(), TlsError> {
        let mut iv = Buffer::new_from_slice(
            self.client_application_iv
                .as_ref()
                .ok_or(TlsError::DataExhausted)?
                .slice(),
        );
        prepare_iv(&mut iv, self.records_received);

        let encrypted = self.encrypt_application_data(iv, data);
        self.stream
            .write(encrypted.slice())
            .map_err(|_| TlsError::IoError)?;
        self.stream.flush().map_err(|_| TlsError::IoError)?;
        self.records_sent += 1;
        Ok(())
    }

    fn receive_data(&mut self) -> Result<(u8, Buffer<MAX_RECORD_SIZE>), TlsError> {
        let (_, record) = self.read_record_to_buffer::<MAX_RECORD_SIZE>()?;
        let mut iv: Buffer<12> = Buffer::new_from_slice(
            self.server_application_iv
                .as_ref()
                .ok_or(TlsError::DataExhausted)?
                .slice(),
        );
        prepare_iv(&mut iv, self.records_received);
        let plaintext = decrypt(
            self.server_application_key
                .as_ref()
                .ok_or(TlsError::DataExhausted)?,
            &iv,
            &record,
        );
        self.records_received += 1;

        let record_type = plaintext.get_unchecked(plaintext.len());
        log::trace!("RECORD TYPE => {:02x}", record_type);

        if record_type == 0x15 && plaintext.slice()[1] == 0x00 {
            Err(TlsError::ConnectionClosed)
        } else {
            Ok((record_type, plaintext))
        }
    }
}

fn prepare_iv(iv: &mut Buffer<12>, msg_num: u64) {
    iv.slice_mut()[11] ^= (msg_num & 0xff) as u8;
    iv.slice_mut()[10] ^= ((msg_num & 0xff00) << 8) as u8;
    iv.slice_mut()[9] ^= ((msg_num & 0xff0000) << 16) as u8;
    iv.slice_mut()[8] ^= ((msg_num & 0xff000000) << 24) as u8;
    iv.slice_mut()[7] ^= ((msg_num & 0xff00000000) << 32) as u8;
    iv.slice_mut()[6] ^= ((msg_num & 0xff0000000000) << 40) as u8;
    iv.slice_mut()[5] ^= ((msg_num & 0xff0000000000) << 48) as u8;
    iv.slice_mut()[4] ^= ((msg_num & 0xff0000000000) << 56) as u8;
}

fn decrypt(
    key: &Buffer<16>,
    iv: &Buffer<12>,
    contents: &Buffer<MAX_RECORD_SIZE>,
) -> Buffer<MAX_RECORD_SIZE> {
    let key = Key::from_slice(key.slice());
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(iv.slice()); // 96-bits; unique per message

    let mut buffer = Buffer::new_from_slice(&contents.slice()[5..]);
    cipher
        .decrypt_in_place(nonce, &contents.slice()[..5], &mut buffer)
        .unwrap();

    buffer
}

fn encrypt<const SIZE: usize>(
    key: &Buffer<16>,
    iv: &Buffer<12>,
    plaintext: &Buffer<SIZE>,
    additional: &Buffer<5>,
) -> Buffer<SIZE> {
    let key = Key::from_slice(key.slice());
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(iv.slice()); // 96-bits; unique per message

    let mut buffer = Buffer::<SIZE>::new_from_slice(&plaintext.slice());
    cipher
        .encrypt_in_place(nonce, &additional.slice(), &mut buffer)
        .unwrap();

    let mut res = Buffer::<SIZE>::new();
    res.push(additional.slice());
    res.push(buffer.slice());
    res
}

fn is_final_handshake_message(data: &[u8]) -> bool {
    let mut idx = 0;

    loop {
        let msg_type = data[idx];
        let msg_len =
            data[idx + 3] as usize | (data[idx + 2] as usize) << 8 | (data[idx + 1] as usize) << 16;

        if msg_type == 0x14 {
            return true;
        }

        idx += msg_len + 4;

        if idx >= data.len() {
            break;
        }
    }

    false
}

impl<'a, T, const HANDSHAKE_BUFFER_SIZE: usize> Io for Session<'a, T, HANDSHAKE_BUFFER_SIZE>
where
    T: Read + Write,
{
    type Error = TlsError;
}

impl<'a, T, const HANDSHAKE_BUFFER_SIZE: usize> Read for Session<'a, T, HANDSHAKE_BUFFER_SIZE>
where
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        log::trace!("read {} bytes", buf.len());

        if !self.connected {
            self.connect()?;
            self.connected = true;
        }

        if buf.len() == 0 {
            return Ok(0);
        }

        let mut idx = 0;

        fn fill_buffer(
            idx: &mut usize,
            current_data: &mut Option<Buffer<MAX_RECORD_SIZE>>,
            buf: &mut [u8],
        ) {
            if let Some(ref mut data) = current_data {
                loop {
                    if *idx >= buf.len() {
                        break;
                    }

                    if let Some(byte) = data.read() {
                        buf[*idx] = byte;
                        *idx += 1;
                    } else {
                        break;
                    }
                }
            }
        }

        fill_buffer(&mut idx, &mut self.current_data, buf);

        if let Some(error_to_report) = self.defered_error {
            if idx == 0 {
                return Err(error_to_report);
            }
        }

        if idx < buf.len() {
            match self.receive_data() {
                Ok((record_type, data)) => {
                    if record_type == 0x17 {
                        self.current_data = Some(data);
                    }
                }
                Err(err) => {
                    self.defered_error = Some(err);
                }
            }
        }

        fill_buffer(&mut idx, &mut self.current_data, buf);

        Ok(idx)
    }
}

impl<'a, T, const HANDSHAKE_BUFFER_SIZE: usize> Write for Session<'a, T, HANDSHAKE_BUFFER_SIZE>
where
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        log::trace!("write {} bytes", buf.len());

        if !self.connected {
            self.connect()?;
            self.connected = true;
        }

        for chunk in buf.chunks(MAX_SUPPORT_SEND_RECORD_SIZE) {
            let buffer: Buffer<MAX_SUPPORT_SEND_RECORD_SIZE> = Buffer::new_from_slice(chunk);
            self.send_data(buffer)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if let Err(_err) = self.stream.flush() {
            Err(TlsError::IoError)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use embedded_io::{
        blocking::{Read, Write},
        Io,
    };
    extern crate std;
    use std::println;
    use std::vec::*;

    const CLIENT_EPHEMERAL_PRIVATE: &str =
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const CLIENT_HELLO: &str = "16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304";
    const SERVER_HELLO: &str = "160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304";
    const WRAPPER: &str = "1703030475da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584ce08b0e455a350ae54d76349aa68c71ae";

    #[test]
    fn test_handshake() {
        env_logger::init();

        let mut data = Vec::new();
        data.append(&mut hex::decode(SERVER_HELLO).unwrap());
        data.append(&mut hex::decode("140303000101").unwrap());
        data.append(&mut hex::decode(WRAPPER).unwrap());

        let io = MockInputOutput::new(data);
        let random = [0u8; 32];
        let mut key: [u8; 32] = [0u8; 32];
        hex::decode_to_slice(CLIENT_EPHEMERAL_PRIVATE, &mut key).unwrap();

        let mut tls: Session<'_, MockInputOutput, 4096> =
            Session::new_test(io, "www.google.com", random, key);
        let mut handshake_data = HandshakeData {
            _server_random: None,
            server_public_key: None,
            client_hello: None,
            server_hello: None,
            client_handshake_key: None,
            server_handshake_key: None,
            client_handshake_iv: None,
            server_handshake_iv: None,
            server_handshake: None,
            handshake_secret: None,
            client_handshake_secret: None,
        };

        handshake_data.client_hello =
            Some(Buffer::new_from_slice(&hex::decode(CLIENT_HELLO).unwrap()));

        tls.test_process_server_hello(&mut handshake_data).unwrap();

        println!(
            "ClientHello {:02x?}",
            handshake_data.client_hello.as_ref().unwrap().slice()
        );
        println!(
            "ServerHello {:02x?}",
            handshake_data.server_hello.as_ref().unwrap().slice()
        );
        println!(
            "client_handshake_key {:02x?}",
            handshake_data
                .client_handshake_key
                .as_ref()
                .unwrap()
                .slice()
        );

        assert!(
            handshake_data
                .client_handshake_key
                .as_ref()
                .unwrap()
                .slice()
                == &hex::decode("7154f314e6be7dc008df2c832baa1d39").unwrap()
        );
        assert!(
            handshake_data
                .server_handshake_key
                .as_ref()
                .unwrap()
                .slice()
                == &hex::decode("844780a7acad9f980fa25c114e43402a").unwrap()
        );
        assert!(
            handshake_data.client_handshake_iv.as_ref().unwrap().slice()
                == &hex::decode("71abc2cae4c699d47c600268").unwrap()
        );
        assert!(
            handshake_data.server_handshake_iv.as_ref().unwrap().slice()
                == &hex::decode("4c042ddc120a38d1417fc815").unwrap()
        );

        assert!(
            tls.client_application_key.as_ref().unwrap().slice()
                == &hex::decode("49134b95328f279f0183860589ac6707").unwrap()
        );
        assert!(
            tls.client_application_iv.as_ref().unwrap().slice()
                == &hex::decode("bc4dd5f7b98acff85466261d").unwrap()
        );
        assert!(
            tls.server_application_key.as_ref().unwrap().slice()
                == &hex::decode("0b6d22c8ff68097ea871c672073773bf").unwrap()
        );
        assert!(
            tls.server_application_iv.as_ref().unwrap().slice()
                == &hex::decode("1b13dd9f8d8f17091d34b349").unwrap()
        );

        assert_eq!(
            tls.generate_verify_data(&mut handshake_data).slice(),
            &hex::decode("976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b")
                .unwrap()
        );

        assert_eq!(
            tls.encrypt_application_data(
                tls.client_application_iv.clone().unwrap(),
                Buffer::new_from_slice(b"ping")
            )
            .slice(),
            &hex::decode("1703030015c74061535eb12f5f25a781957874742ab7fb305dd5").unwrap()
        );
    }

    struct MockInputOutput {
        server_data: Vec<u8>,
        index: usize,
    }

    impl MockInputOutput {
        fn new(server_data: Vec<u8>) -> MockInputOutput {
            MockInputOutput {
                server_data,
                index: 0,
            }
        }
    }

    #[allow(dead_code)]
    #[derive(Debug)]
    enum IoError {
        Other,
    }

    impl embedded_io::Error for IoError {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::Other
        }
    }

    impl Io for MockInputOutput {
        type Error = IoError;
    }

    impl Read for MockInputOutput {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = usize::min(self.server_data.len() - self.index, buf.len());
            buf[..len].copy_from_slice(&self.server_data.as_slice()[self.index..][..len]);
            self.index += len;
            Ok(len)
        }
    }

    impl Write for MockInputOutput {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            // nothing
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
