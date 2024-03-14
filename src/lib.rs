/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

#![doc = include_str!("../README.md")]

mod crypto;
pub use crypto::*;

use std::{collections::BTreeMap, error::Error, fs::File};
use uuid::Uuid;

/// specifies the encryption mode for a given message being sent.
pub enum SendMode {
    Dh,
    Hmac,
    Session,
    Kem,
}

/// facilitates `Interaction` binding to a remote.
pub trait Connection {
    fn create_stream(&self) -> Result<Uuid, Box<dyn Error>>;

    fn send(&self, id: Uuid, encrypted: &[u8]) -> Result<Uuid, Box<dyn Error>>;
    fn recv(&self, id: Uuid, position: usize) -> Result<Vec<Vec<u8>>, Box<dyn Error>>;
}

struct SendStream<'a, T: Connection> {
    connection: &'a T,

    id: Uuid,

    hmac_key: Option<[u8; 32]>,
    last_key: (usize, Option<[u8; 32]>),

    dh_priv: [u8; 32],
    dh_pubs: Vec<[u8; 32]>,
    usernames: Vec<String>,
}

impl<'a, T: Connection> SendStream<'a, T> {
    pub fn new(connection: &'a T) -> Self {
        let (dh_priv, _) = generate_dh_keys();

        let uuid = Uuid::new_v4();
        // TODO: write file with uuid as name

        Self {
            connection,

            id: uuid,

            hmac_key: None,
            last_key: (0, None),

            dh_priv,
            dh_pubs: vec![],
            usernames: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        // TODO: write to the kem key file

        let uuid = Uuid::from_bytes([0; 16]);

        let dh_priv = [0u8; 32];

        Self {
            connection,

            id: uuid,

            hmac_key: Some([0u8; 32]),
            last_key: (0, Some([0u8; 32])),

            dh_priv,
            dh_pubs: vec![],
            usernames: vec![],
        }
    }

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    fn kem_key_reader(&self) -> KemKeyReader<File> {
        let file = File::open(self.id.to_string()).unwrap();
        KemKeyReader::new_dh_hybrid(self.dh_priv, file)
    }

    pub fn send(&mut self, content: Vec<u8>, mode: SendMode) -> Result<(), Box<dyn Error>> {
        // TODO: use the sender's fingerprint
        let (fingerprint, _) = crate::generate_fingerprint();

        let (mode, new_itr) = match mode {
            SendMode::Dh => (Encrypt::Dh(self.dh_priv, &self.dh_pubs, None), 0),
            SendMode::Hmac => (
                Encrypt::Hmac(
                    self.hmac_key.unwrap(),
                    self.last_key.1.unwrap(),
                    self.last_key.0,
                ),
                self.last_key.0 + 1,
            ),
            SendMode::Session => (
                Encrypt::Session(self.last_key.1.unwrap(), false),
                self.last_key.0,
            ),
            SendMode::Kem => (Encrypt::Kem(self.kem_key_reader()), 0),
        };

        let (encrypted_content, key) = encrypt(fingerprint, content, mode)?;

        self.last_key.0 = new_itr;
        self.last_key.1 = Some(key);

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
    hmac_key: [u8; sizes::KEY_SIZE],
    last_key: (usize, [u8; sizes::KEY_SIZE]),

    dh_pub: [u8; sizes::KEY_SIZE],
    dh_priv: [u8; sizes::KEY_SIZE],

    kem_secret: [u8; sizes::KEM_SECRET_KEY_SIZE],

    verifier: [u8; sizes::KEY_SIZE],
}

impl<'a, T: Connection> RecvStream<'a, T> {
    pub fn from_bytes(bytes: &[u8], connection: &'a T) {}

    pub fn to_bytes() -> Vec<u8> {
        vec![]
    }

    pub fn recv(&mut self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let mut encrypted_msgs = self.connection.recv(self.id, self.position)?;

        let mut out: Vec<Vec<u8>> = vec![];

        for encrypted_msg in &mut encrypted_msgs {
            let (decrypted, key) = match extract_components_mut(self.position, encrypted_msg) {
                Components::Dh(encrypted_key, with_hmac) => {
                    if with_hmac {
                        decrypt(
                            Some(&self.verifier),
                            encrypted_msg,
                            Decrypt::Dh(
                                encrypted_key,
                                self.dh_priv,
                                self.dh_pub,
                                Some(self.hmac_key),
                            ),
                        )?
                    } else {
                        decrypt(
                            Some(&self.verifier),
                            encrypted_msg,
                            Decrypt::Dh(encrypted_key, self.dh_priv, self.dh_pub, None),
                        )?
                    }
                }
                Components::Hmac(itr) => {
                    // TODO: do stuff with itr

                    decrypt(
                        Some(&self.verifier),
                        encrypted_msg,
                        Decrypt::Hmac(self.hmac_key, self.last_key.1),
                    )?
                }
                Components::Session(encrypted_key) => decrypt(
                    Some(&self.verifier),
                    encrypted_msg,
                    Decrypt::Session(self.last_key.1, encrypted_key),
                )?,
                Components::Kem(encrypted_key, ciphertext, is_dh_hybrid) => {
                    if is_dh_hybrid {
                        decrypt(
                            Some(&self.verifier),
                            encrypted_msg,
                            Decrypt::Kem(
                                encrypted_key,
                                ciphertext,
                                self.kem_secret,
                                Some((self.dh_pub, self.dh_priv)),
                            ),
                        )?
                    } else {
                        decrypt(
                            Some(&self.verifier),
                            encrypted_msg,
                            Decrypt::Kem(encrypted_key, ciphertext, self.kem_secret, None),
                        )?
                    }
                }
            };

            self.last_key = (0, key);

            out.push(decrypted)
        }

        Ok(out)
    }
}

/// the unifying interface for a collection of encrypted message streams.
pub struct Interaction<'a, T: Connection> {
    id: Uuid,

    send_stream: SendStream<'a, T>,
    recv_streams: Vec<RecvStream<'a, T>>,

    // initialization timestamp -> keys
    dh_keys: BTreeMap<u64, ([u8; sizes::KEY_SIZE], [u8; sizes::KEY_SIZE])>,
    kem_keys: BTreeMap<u64, [u8; sizes::KEM_SECRET_KEY_SIZE]>,
}

impl<'a, T: Connection> Interaction<'a, T> {
    pub fn new(connection: &'a T) -> Self {
        Self {
            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            dh_keys: BTreeMap::new(),
            kem_keys: BTreeMap::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8], connection: &'a T) -> Self {
        Self {
            id: Uuid::new_v4(),

            send_stream: SendStream::new(connection),
            recv_streams: vec![],

            dh_keys: BTreeMap::new(),
            kem_keys: BTreeMap::new(),
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

        for recv_stream in &mut self.recv_streams {
            let messages = recv_stream.recv()?;
            out.extend(messages);
        }

        Ok(out)
    }
}
