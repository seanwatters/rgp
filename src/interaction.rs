use std::error::Error;
use uuid::Uuid;

use crate::EncryptMode;

pub trait Connection {
    fn create_stream(&self) -> Result<Uuid, Box<dyn Error>>;

    fn push(&self, id: Uuid) -> Result<(), Box<dyn Error>>;
    fn pull(&self, id: Uuid) -> Result<Vec<&[u8]>, Box<dyn Error>>;
}

struct SendStream<'a, T: Connection> {
    connection: &'a T,

    id: Uuid,

    // initialized as a constant but can be set
    hmac_key: [u8; 32],
    // (iteration for current hmac_key, current key value)
    last_key: (u64, [u8; 32]),

    // `dh_keys` and `usernames` are ordered and correlated
    dh_keys: Vec<[u8; 32]>,
    usernames: Vec<String>,
}

impl<'a, T: Connection> SendStream<'a, T> {
    pub fn new(connection: &'a T) -> Self {
        Self {
            connection,

            id: Uuid::new_v4(),

            hmac_key: [0u8; 32],
            last_key: (0, [0u8; 32]),

            dh_keys: vec![],
            usernames: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        Self {
            connection,

            id: Uuid::new_v4(),

            hmac_key: [0u8; 32],
            last_key: (0, [0u8; 32]),

            dh_keys: vec![],
            usernames: vec![],
        }
    }

    pub fn push(&self, mode: EncryptMode) {}
}

struct RecvStream<'a, T: Connection> {
    connection: &'a T,

    id: Uuid,
    position: u64,

    // TODO: will need to handle OOO messages
    // TODO: and only increment these values once
    // TODO: we know we've seen every increment on
    // TODO: the iterator up until that point by storing
    // TODO: a "seen_iterators" so that we can build up
    // TODO: [2, 3, 4, 5], while we wait for 1 to come in
    // TODO: (once 1 comes in, we can set to 5).
    hmac_key: [u8; 32],
    last_key: (u64, [u8; 32]),
}

impl<'a, T: Connection> RecvStream<'a, T> {
    pub fn from_bytes(bytes: &[u8], connection: &'a T) {}

    pub fn pull(&self) {}
}

pub struct Interaction<'a, T: Connection> {
    connection: &'a T,

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
            connection,

            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            recv_keys: vec![],
        }
    }

    /// `Interaction` on-disk format
    ///
    /// - receive streams count
    ///     - size = 2 bits
    ///     - count = 0-8 bytes
    /// - receive stream * receive streams count
    ///     - id = 16 bytes
    ///     - position
    ///         - size = 2 bits
    ///         - position = 0-8 bytes
    ///     - hmac_key = 32 bytes (encrypted)
    ///     - last_key (encrypted)
    ///         - iteration
    ///             - size = 2 bits
    ///             - iteration = 0-8 bytes
    ///         - value = 32 bytes
    ///
    /// - send stream
    ///     - id = 16 bytes
    ///     - hmac_key = 32 bytes (encrypted)
    ///     - last_key (encrypted)
    ///         - iteration
    ///             - size = 2 bits
    ///             - iteration = 0-8 bytes
    ///         - value = 32 bytes
    ///     - recipients count
    ///         - size = 2 bits
    ///         - count = 0-8 bytes
    ///     - dh_keys = 32 bytes * recipient count
    ///     - usernames = variable bytes * recipient count (encrypted)
    ///
    /// - recv_keys
    ///     - start = 8 bytes
    ///     - end = 8 bytes
    ///     - pub key = 32 bytes
    ///     - priv key = 32 bytes (encrypted)
    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        Self {
            connection,

            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            recv_keys: vec![],
        }
    }

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn push(&self, mode: EncryptMode) {
        self.send_stream.push(mode)
    }

    pub fn pull_all(&self) {
        for recv_stream in &self.recv_streams {
            recv_stream.pull()
        }
    }
}

// ?? will need a "bootstrapping stream" for adding a new user to an interaction
//  * sharing your public key for them to encrypt with
//  * sharing their position on your send stream
//  * sharing the current ratchet state
//  * sharing any "historical keys" for your stream

// ?? will also need "repair streams" maybe? but those will likely just be identical to
// ?? bootstrapping streams as they serve the same "re-sync" purpose.
