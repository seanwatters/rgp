pub enum SendMode {
    /// PGP-style fresh session key for each message.
    ///
    /// most secure, and highest overhead (32 bytes for each recipient).
    KeyGen,

    /// Increments ratchet.
    ///
    /// less secure, but keys still appear random to attackers, and there
    /// is maybe better break-in recovery if a `ratchet_key` is used. much lower
    /// overhead as keys don't need to be encrypted or stored for every recipient.
    Ratchet,

    /// Reuses most recent ratchet key.
    ///
    /// least secure as it provides no forward secrecy, but may be useful for
    /// applications that need RTC where the ratchet operation would bog things down
    /// too much, but the usage context can afford to have a series of frames reuse
    /// the same key (i.e Session send mode is used for the duration of a phone
    /// call or video chat or something).
    Session,
}

struct SendStream {
    id: [u8; 16],

    // initialized as a constant, but could be set to possibly improve break-in recovery?
    ratchet_key: [u8; 32],
    // (iteration for current ratchet_key, current ratchet value)
    ratchet_value: (u64, [u8; 32]),

    // `send_keys` and `usernames` are ordered and correlated
    send_keys: Vec<[u8; 32]>,
    usernames: Vec<String>,
}

impl SendStream {
    pub fn put(&self, mode: SendMode) {}
}

struct RecvStream {
    id: [u8; 16],
    position: u64,

    // TODO: will need to handle OOO messages
    // TODO: and only increment these values once
    // TODO: we know we've seen every increment on
    // TODO: the iterator up until that point by storing
    // TODO: a "seen_iterators" so that we can build up
    // TODO: [2, 3, 4, 5], while we wait for 1 to come in
    // TODO: (once 1 comes in, we can set to 5).
    ratchet_key: [u8; 32],
    ratchet_value: (u64, [u8; 32]),
}

impl RecvStream {
    pub fn sync(&self) {}
}

/*
`Interaction` on-disk format

- receive streams count
    - size = 2 bits
    - count = 0-8 bytes
- receive stream * receive streams count
    - id = 16 bytes
    - position
        - size = 2 bits
        - position = 0-8 bytes
    - ratchet_key = 32 bytes (encrypted)
    - ratchet_value (encrypted)
        - iteration
            - size = 2 bits
            - iteration = 0-8 bytes
        - value = 32 bytes

- send stream
    - id = 16 bytes
    - ratchet_key = 32 bytes (encrypted)
    - ratchet_value (encrypted)
        - iteration
            - size = 2 bits
            - iteration = 0-8 bytes
        - value = 32 bytes
    - recipients count
        - size = 2 bits
        - count = 0-8 bytes
    - send_keys = 32 bytes * recipient count
    - usernames = variable bytes * recipient count (encrypted)

- recv_keys
    - start = 8 bytes
    - end = 8 bytes
    - pub key = 32 bytes
    - priv key = 32 bytes (encrypted)
*/
struct Interaction {
    id: [u8; 16],

    send_stream: SendStream,
    recv_streams: Vec<RecvStream>,

    // probably should be a BTreeMap but for now
    // we're just tracking (start, end, pub key, priv key) in a tuple
    recv_keys: Vec<(u64, u64, [u8; 32], [u8; 32])>,
}

impl Interaction {
    pub fn put(&self, mode: SendMode) {
        self.send_stream.put(mode)
    }

    pub fn sync_all(&self) {
        for recv_stream in &self.recv_streams {
            recv_stream.sync()
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
