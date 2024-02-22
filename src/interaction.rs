use std::error::Error;
use uuid::Uuid;

use crate::{decrypt, encrypt, extract_mode_mut, generate_dh_keys, DecryptMode, EncryptMode, Mode};

pub enum SendMode {
    Dh,
    Hmac,
    Session,
}

/// facilitates binding to remote for `Interactions`.
pub trait Connection {
    fn create_stream(&self) -> Result<Uuid, Box<dyn Error>>;

    fn send(&self, id: Uuid, encrypted: &[u8]) -> Result<Uuid, Box<dyn Error>>;
    fn recv(&self, id: Uuid, position: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>>;
}

struct SendStream<'a, T: Connection> {
    connection: &'a T,

    id: Uuid,

    // initialized as a constant but can be set
    hmac_key: [u8; 32],
    // (iteration for current hmac_key, current key value)
    last_key: (usize, [u8; 32]),

    dh_priv: [u8; 32],
    // `dh_pubs` and `usernames` are ordered and correlated
    dh_pubs: Vec<[u8; 32]>,
    usernames: Vec<String>,
}

impl<'a, T: Connection> SendStream<'a, T> {
    pub fn new(connection: &'a T) -> Self {
        let (dh_priv, _) = generate_dh_keys();

        Self {
            connection,

            id: Uuid::new_v4(),

            hmac_key: [0u8; 32],
            last_key: (0, [0u8; 32]),

            dh_priv,
            dh_pubs: vec![],
            usernames: vec![],
        }
    }

    /// bytes format
    ///
    /// - id = 16 bytes
    /// - hmac_key = 32 bytes (encrypted)
    /// - last_key (encrypted)
    ///     - iteration
    ///         - size = 2 bits
    ///         - iteration = 0-8 bytes
    ///     - value = 32 bytes
    /// - recipients count
    ///     - size = 2 bits
    ///     - count = 0-8 bytes
    /// - dh_pubs = 32 bytes * recipient count
    /// - usernames = variable bytes * recipient count (encrypted)
    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        Self {
            connection,

            id: Uuid::new_v4(),

            hmac_key: [0u8; 32],
            last_key: (0, [0u8; 32]),

            dh_priv: [0u8; 32],
            dh_pubs: vec![],
            usernames: vec![],
        }
    }

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn send(&mut self, content: Vec<u8>, mode: SendMode) -> Result<(), Box<dyn Error>> {
        // TODO: use the sender's fingerprint
        let (fingerprint, _) = crate::generate_fingerprint();

        let (mode, new_itr) = match mode {
            SendMode::Dh => (EncryptMode::Dh(self.dh_priv, &self.dh_pubs), 0),
            SendMode::Hmac => (
                EncryptMode::Hmac(self.hmac_key, self.last_key.1, self.last_key.0),
                self.last_key.0 + 1,
            ),
            SendMode::Session => (EncryptMode::Session(self.last_key.1), self.last_key.0),
        };

        let (encrypted_content, key) = encrypt(fingerprint, content, mode)?;

        self.last_key.0 = new_itr;
        self.last_key.1 = key;

        self.connection.send(self.id, &encrypted_content)?;

        Ok(())
    }
}

struct RecvStream<'a, T: Connection> {
    connection: &'a T,

    id: Uuid,
    position: usize,

    // ?? will need to handle OOO messages
    // ?? and only increment these values once
    // ?? we know we've seen every increment on
    // ?? the iterator up until that point by storing
    // ?? a "seen_iterators" so that we can build up
    // ?? [2, 3, 4, 5], while we wait for 1 to come in
    // ?? (once 1 comes in, we can set to 5).
    hmac_key: [u8; 32],
    last_key: (usize, [u8; 32]),

    dh_pub: [u8; 32],
    dh_priv: [u8; 32],

    verifying_key: [u8; 32],
}

impl<'a, T: Connection> RecvStream<'a, T> {
    /// bytes format
    ///
    /// - id = 16 bytes
    /// - position
    ///     - size = 2 bits
    ///     - position = 0-8 bytes
    /// - hmac_key = 32 bytes (encrypted)
    /// - last_key (encrypted)
    ///     - iteration
    ///         - size = 2 bits
    ///         - iteration = 0-8 bytes
    ///     - value = 32 bytes
    pub fn from_bytes(bytes: &[u8], connection: &'a T) {}

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn recv(&mut self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let mut encrypted_msgs = self.connection.recv(self.id, self.position)?;

        let mut out: Vec<Vec<u8>> = vec![];

        for encrypted_msg in &mut encrypted_msgs {
            let (decrypted, key) = match extract_mode_mut(self.position, encrypted_msg) {
                Mode::Dh(content_key) => decrypt(
                    Some(&self.verifying_key),
                    encrypted_msg,
                    DecryptMode::Dh(content_key, self.dh_priv, self.dh_pub),
                )?,
                Mode::Hmac(itr) => {
                    // TODO: do stuff with itr

                    decrypt(
                        Some(&self.verifying_key),
                        encrypted_msg,
                        DecryptMode::Hmac(self.hmac_key, self.last_key.1),
                    )?
                }
                Mode::Session => decrypt(
                    Some(&self.verifying_key),
                    encrypted_msg,
                    DecryptMode::Session(self.last_key.1),
                )?,
            };

            self.last_key = (0, key);

            out.push(decrypted)
        }

        Ok(out)
    }
}

pub struct Interaction<'a, T: Connection> {
    id: Uuid,

    send_stream: SendStream<'a, T>,
    recv_streams: Vec<RecvStream<'a, T>>,

    // probably should be a BTreeMap but for now
    // we're just tracking (start, end, pub key, priv key) in a tuple
    recv_keys: Vec<(u64, u64, [u8; 32], [u8; 32])>,
}

impl<'a, T: Connection> Interaction<'a, T> {
    pub fn new(connection: &'a T) -> Self {
        Self {
            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            recv_keys: vec![],
        }
    }

    /// bytes format
    ///
    /// - receive streams count
    ///     - size = 2 bits
    ///     - count = 0-8 bytes
    /// - send stream = ?
    /// - receive streams
    ///     - count
    ///         - size = 2 bits
    ///         - count = 0-8 bytes
    ///     - streams = ? * receive streams count
    /// - recv_keys
    ///     - count
    ///         - size = 2 bits
    ///         - count = 0-8 bytes
    ///     - start = 8 bytes
    ///     - end = 8 bytes
    ///     - pub key = 32 bytes
    ///     - priv key = 32 bytes (encrypted)
    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        Self {
            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            recv_keys: vec![],
        }
    }

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn send(&mut self, content: Vec<u8>, mode: SendMode) -> Result<(), Box<dyn Error>> {
        self.send_stream.send(content, mode)
    }

    pub fn recv_all(&mut self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let mut out: Vec<Vec<u8>> = vec![];

        // TODO: parallelize this
        for recv_stream in &mut self.recv_streams {
            let messages = recv_stream.recv()?;
            out.extend(messages);
        }

        Ok(out)
    }
}

// ?? will need a "bootstrapping stream" for adding a new user to an interaction
//  * sharing your public key for them to encrypt with
//  * sharing their position on your send stream
//  * sharing the current ratchet state
//  * sharing any "historical keys" for your stream

// ?? will also need "repair streams" maybe? but those will likely just be identical to
// ?? bootstrapping streams as they serve the same "re-sync" purpose.
