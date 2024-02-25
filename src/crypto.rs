/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

#[cfg(feature = "multi-thread")]
use rayon::prelude::*;
#[cfg(feature = "multi-thread")]
use std::sync::mpsc::channel;

use std::{
    fs::File,
    io::{BufReader, Read},
};

use blake2::digest::{FixedOutput, Mac};
use chacha20::{
    cipher::{generic_array::GenericArray, typenum, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::{aead::Aead, AeadCore, XChaCha20Poly1305};
use classic_mceliece_rust::{
    decapsulate, encapsulate, keypair as kem_keypair, Ciphertext, PublicKey as KemPublicKey,
    SecretKey as KemSecretKey, CRYPTO_CIPHERTEXTBYTES as KEM_CIPHERTEXT_SIZE,
    CRYPTO_PUBLICKEYBYTES as KEM_PUB_KEY_SIZE, CRYPTO_SECRETKEYBYTES as KEM_SECRET_KEY_SIZE,
};
use ed25519_dalek::{Signer, Verifier};
use x25519_dalek::StaticSecret;

const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

/// generates fingerprints and verifying keys for signing.
///
/// ```rust
/// use rgp::generate_fingerprint;
///
/// let (fingerprint, verifier) = generate_fingerprint();
///
/// assert_eq!(fingerprint.len(), 32);
/// assert_eq!(verifier.len(), 32);
/// ```
pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
    let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    (
        fingerprint.to_bytes(),
        fingerprint.verifying_key().to_bytes(),
    )
}

/// signs content.
#[inline]
fn sign(fingerprint: &[u8; 32], content: &[u8]) -> [u8; 64] {
    let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
    let signature = fingerprint.sign(content);

    signature.to_bytes()
}

/// verifies signatures.
#[inline]
fn verify(signature: &[u8; 64], verifier: &[u8; 32], content: &[u8]) -> Result<(), &'static str> {
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    let verifier = match ed25519_dalek::VerifyingKey::from_bytes(verifier) {
        Ok(vk) => vk,
        Err(_) => return Err("failed to convert verifying key"),
    };

    match verifier.verify(content, &signature) {
        Ok(_) => Ok(()),
        Err(_) => return Err("failed to verify signature"),
    }
}

/// generates `Dh` pub/priv key pairs.
///
/// ```rust
/// use rgp::generate_dh_keys;
///
/// let (priv_key, pub_key) = generate_dh_keys();
///
/// assert_eq!(priv_key.len(), 32);
/// assert_eq!(pub_key.len(), 32);
/// ```
pub fn generate_dh_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

/// generates `Kem` pub/priv key pairs.
///
///```rust
/// use rgp::generate_kem_keys;
///
/// let (secret_key, pub_key) = generate_kem_keys();
///
/// assert_eq!(secret_key.len(), 6492);
/// assert_eq!(pub_key.len(), 261120);
///```
pub fn generate_kem_keys() -> ([u8; KEM_SECRET_KEY_SIZE], [u8; KEM_PUB_KEY_SIZE]) {
    let mut rng = rand::thread_rng();

    let mut public_key_buf = [0u8; KEM_PUB_KEY_SIZE];
    let mut secret_key_buf = [0u8; KEM_SECRET_KEY_SIZE];

    let (pub_key, secret_key) = kem_keypair(&mut public_key_buf, &mut secret_key_buf, &mut rng);

    (*secret_key.as_array(), *pub_key.as_array())
}

#[inline(always)]
fn usize_to_bytes(num: usize) -> Vec<u8> {
    match num {
        0..=63 => vec![(0 << 6) | num as u8],
        64..=318 => vec![((0 << 6) | 63), (num - 63) as u8],
        319..=65_598 => {
            let mut h = vec![(1 << 6) | 63];
            h.extend_from_slice(&((num - 63) as u16).to_be_bytes());
            h
        }
        65_599..=4_294_967_358 => {
            let mut h = vec![(2 << 6) | 63];
            h.extend_from_slice(&((num - 63) as u32).to_be_bytes());
            h
        }
        _ => {
            let mut h = vec![(3 << 6) | 63];
            h.extend_from_slice(&((num - 63) as u64).to_be_bytes());
            h
        }
    }
}

#[inline(always)]
fn bytes_to_usize(bytes: &[u8]) -> (usize, usize) {
    let num_size = bytes[0];

    if num_size < 64 {
        (1, num_size as usize)
    } else {
        match (num_size >> 6) & 0b11 {
            0 => (2, bytes[1] as usize + 63),
            1 => (
                3,
                u16::from_be_bytes(bytes[1..3].try_into().unwrap()) as usize + 63,
            ),
            2 => (
                5,
                u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize + 63,
            ),
            3 => (
                9,
                u64::from_be_bytes(bytes[1..9].try_into().unwrap()) as usize + 63,
            ),
            _ => unreachable!(),
        }
    }
}

#[inline]
fn encrypt_content(
    fingerprint: [u8; 32],
    nonce: &GenericArray<u8, typenum::U24>,
    key: &GenericArray<u8, typenum::U32>,
    content: &mut Vec<u8>,
) -> Result<Vec<u8>, &'static str> {
    use chacha20poly1305::KeyInit;

    let signature = sign(&fingerprint, &content);
    content.extend(signature);

    let content_cipher = XChaCha20Poly1305::new(key);
    match content_cipher.encrypt(nonce, content.as_ref()) {
        Ok(encrypted_content) => Ok(encrypted_content),
        Err(_) => Err("failed to encrypt content"),
    }
}

#[inline]
fn dh_encrypt_keys(
    priv_key: [u8; KEY_SIZE],
    pub_keys: &Vec<[u8; KEY_SIZE]>,
    hmac_key: Option<[u8; KEY_SIZE]>,
    nonce: &GenericArray<u8, typenum::U24>,
    content_key: &GenericArray<u8, typenum::U32>,
) -> (Vec<u8>, Vec<u8>) {
    use chacha20::cipher::KeyIvInit;

    let keys_count = pub_keys.len();
    let header = usize_to_bytes(keys_count);

    let priv_key = StaticSecret::from(priv_key);

    let mut keys = vec![0u8; KEY_SIZE * keys_count];

    #[cfg(feature = "multi-thread")]
    let chunks = keys.par_chunks_mut(KEY_SIZE);
    #[cfg(not(feature = "multi-thread"))]
    let chunks = keys.chunks_mut(KEY_SIZE);

    chunks.enumerate().for_each(|(i, chunk)| {
        let mut key = GenericArray::from(priv_key.diffie_hellman(&pub_keys[i].into()).to_bytes());

        if let Some(hmac_key) = hmac_key {
            key = blake2::Blake2sMac256::new_from_slice(&hmac_key)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();
        }

        let mut key_cipher = XChaCha20::new(&key, nonce);

        let mut content_key = content_key.clone();
        key_cipher.apply_keystream(&mut content_key);

        chunk[0..KEY_SIZE].copy_from_slice(&content_key);
    });

    (header, keys)
}

/// for reading a large volume of McEliece public keys
pub struct KemKeyReader<R: Read> {
    pub reader: BufReader<R>,

    /// for Kem + Dh hybrid
    pub dh_priv_key: Option<[u8; KEY_SIZE]>,
}

impl<R: Read> KemKeyReader<R> {
    /// public key reader with a buffer size of 261120.
    ///
    /// for files that contain only McEliece public keys all in one line.
    pub fn new(source: R) -> Self {
        KemKeyReader {
            reader: BufReader::with_capacity(KEM_PUB_KEY_SIZE, source),
            dh_priv_key: None,
        }
    }

    /// public key reader with a buffer size of 261120 + 32.
    ///
    /// for files that contain McEliece public paired with their
    /// Diffie-Hellman counterparts (i.e Vec<...[u8; ...mc_pub, ...dh_pub]>)
    pub fn new_dh_hybrid(dh_priv_key: [u8; KEY_SIZE], source: R) -> Self {
        KemKeyReader {
            reader: BufReader::with_capacity(KEM_PUB_KEY_SIZE + KEY_SIZE, source),
            dh_priv_key: Some(dh_priv_key),
        }
    }
}

#[inline]
fn kem_encrypt_keys<R: Read>(
    key_reader: &mut KemKeyReader<R>,
    nonce: &GenericArray<u8, typenum::U24>,
    content_key: &GenericArray<u8, typenum::U32>,
) -> (Vec<u8>, Vec<u8>) {
    use chacha20::cipher::KeyIvInit;

    let mut rng = rand::thread_rng();

    let mut key_pos = 0;
    let mut out = vec![];

    // Kem + Dh hybrid
    if let Some(dh_priv_key) = key_reader.dh_priv_key {
        let dh_priv_key = StaticSecret::from(dh_priv_key);

        let mut buf = [0u8; KEM_PUB_KEY_SIZE + KEY_SIZE];

        while let Ok(_) = key_reader.reader.read_exact(&mut buf) {
            let kem_pub_key = buf[0..KEM_PUB_KEY_SIZE].try_into().unwrap();
            let kem_pub_key = KemPublicKey::from(&kem_pub_key);

            let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
            let (kem_ciphertext, kem_shared_secret) =
                encapsulate(&kem_pub_key, &mut kem_shared_secret_buf, &mut rng);

            let mut key = GenericArray::from(*kem_shared_secret.as_array());

            let dh_pub_key: [u8; KEY_SIZE] = buf[KEM_PUB_KEY_SIZE..KEM_PUB_KEY_SIZE + KEY_SIZE]
                .try_into()
                .unwrap();
            let dh_shared_secret = dh_priv_key.diffie_hellman(&dh_pub_key.into()).to_bytes();

            // HMAC the KEM shared secret with the Diffie-Hellman shared secret
            key = blake2::Blake2sMac256::new_from_slice(&dh_shared_secret)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();

            let mut key_cipher = XChaCha20::new(&key, nonce);

            let mut content_key = content_key.clone();
            key_cipher.apply_keystream(&mut content_key);

            out.extend(content_key);
            out.extend(kem_ciphertext.as_array());

            key_pos += 1;
        }
    } else {
        // raw Kem

        let mut buf = [0u8; KEM_PUB_KEY_SIZE];

        while let Ok(_) = key_reader.reader.read_exact(&mut buf) {
            let kem_pub_key = KemPublicKey::from(&buf);

            let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
            let (kem_ciphertext, kem_shared_secret) =
                encapsulate(&kem_pub_key, &mut kem_shared_secret_buf, &mut rng);

            let key = GenericArray::from(*kem_shared_secret.as_array());

            let mut key_cipher = XChaCha20::new(&key, nonce);

            let mut content_key = content_key.clone();
            key_cipher.apply_keystream(&mut content_key);

            out.extend(content_key);
            out.extend(kem_ciphertext.as_array());

            key_pos += 1;
        }
    }

    let header = usize_to_bytes(key_pos);

    (header, out)
}

/// encapsulates the parameters and mode for encryption.
pub enum Encrypt<'a, R: Read = File> {
    /// generates random content key and encrypts for all
    /// recipients with their respective Diffie-Hellman shared secret.
    Dh(
        /// sender private key
        [u8; KEY_SIZE],
        /// recipient public keys
        &'a Vec<[u8; KEY_SIZE]>,
        /// optional HMAC key
        Option<[u8; KEY_SIZE]>,
    ),

    /// hashes the second tuple member, with the first
    /// tuple member as the HMAC key.
    Hmac(
        /// HMAC key
        [u8; KEY_SIZE],
        /// HMAC value
        [u8; KEY_SIZE],
        /// iteration
        usize,
    ),

    /// uses the key that is passed in without modification.
    Session(
        /// session key
        [u8; KEY_SIZE],
        /// with key gen
        bool,
    ),

    /// uses key encapsulation to encrypt a copy of the
    /// a one-time generated content key for each recipient.
    Kem(
        /// recipient KEM public keys reader
        KemKeyReader<R>,
    ),
}

/// signs and encrypts content.
///
/// ```rust
/// # use rgp::{decrypt, extract_components_mut, Components, Decrypt, generate_dh_keys, generate_fingerprint};
/// # let (sender_priv_key, sender_pub_key) = generate_dh_keys();
/// # let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();
/// # let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();
/// # let (hmac_key, hmac_value) = generate_dh_keys();
/// # let (session_key, _) = generate_dh_keys();
/// # let itr = 0;
/// # let (fingerprint, verifier) = generate_fingerprint();
/// #
/// use rgp::{encrypt, Encrypt};
///
/// let content = vec![0u8; 1024];
/// # let content_clone = content.clone();
/// # let recipient_pub_keys = vec![receiver_pub_key];
///
/// // Dh
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     Encrypt::Dh(sender_priv_key, &recipient_pub_keys, None)
/// ).unwrap();
/// # if let Components::Dh(encrypted_key, _) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Dh(encrypted_key, sender_pub_key, receiver_priv_key, None),
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
///
/// // Hmac
/// # let content = content_clone.clone();
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     Encrypt::Hmac(hmac_key, hmac_value, itr)
/// ).unwrap();
/// # if let Components::Hmac(iteration) = extract_components_mut(0, &mut encrypted_content) {
/// #     assert_eq!(iteration, itr);
/// #
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Hmac(hmac_key, hmac_value),
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
///
/// // Session
/// # let content = content_clone.clone();
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     Encrypt::Session(session_key, false)
/// ).unwrap();
/// # if let Components::Session(encrypted_key) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Session(session_key, encrypted_key),
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
/// ```
pub fn encrypt(
    fingerprint: [u8; 32],
    mut content: Vec<u8>,
    mode: Encrypt,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    match mode {
        Encrypt::Session(session_key, with_key_gen) => {
            if with_key_gen {
                let content_key = {
                    use chacha20poly1305::KeyInit;
                    XChaCha20Poly1305::generate_key(&mut rand_core::OsRng)
                };

                let mut key_cipher = {
                    use chacha20::cipher::KeyIvInit;
                    XChaCha20::new(&session_key.into(), &nonce)
                };

                let encrypted_content =
                    encrypt_content(fingerprint, &nonce, &content_key, &mut content)?;

                let mut encrypted_key = content_key.clone();
                key_cipher.apply_keystream(&mut encrypted_key);

                out.extend(encrypted_key);
                out.extend(encrypted_content);

                out.push(3);

                Ok((out, content_key.into()))
            } else {
                let encrypted_content =
                    encrypt_content(fingerprint, &nonce, &session_key.into(), &mut content)?;
                out.extend(encrypted_content);

                out.push(0);

                Ok((out, session_key))
            }
        }
        Encrypt::Hmac(hash_key, key, itr) => {
            let key = blake2::Blake2sMac256::new_from_slice(&hash_key)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();

            let itr_as_bytes = usize_to_bytes(itr);
            out.extend(itr_as_bytes);

            let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content)?;
            out.extend(encrypted_content);

            out.push(1);

            Ok((out, key.into()))
        }
        Encrypt::Dh(priv_key, pub_keys, hmac_key) => {
            use chacha20poly1305::KeyInit;
            let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

            #[cfg(feature = "multi-thread")]
            let (sender, receiver) = channel();

            #[cfg(feature = "multi-thread")]
            rayon::spawn(move || {
                let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content);
                sender.send(encrypted_content).unwrap();
            });

            let (header, keys) = dh_encrypt_keys(priv_key, pub_keys, hmac_key, &nonce, &key);
            out.extend(header);
            out.extend(keys);

            #[cfg(feature = "multi-thread")]
            let encrypted_content = receiver.recv().unwrap()?;
            #[cfg(not(feature = "multi-thread"))]
            let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content)?;

            out.extend(encrypted_content);

            out.push(if hmac_key.is_some() { 4 } else { 2 });

            Ok((out, key.into()))
        }
        Encrypt::Kem(mut key_reader) => {
            use chacha20poly1305::KeyInit;
            let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

            #[cfg(feature = "multi-thread")]
            let (sender, receiver) = channel();

            #[cfg(feature = "multi-thread")]
            rayon::spawn(move || {
                let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content);
                sender.send(encrypted_content).unwrap();
            });

            let (header, keys) = kem_encrypt_keys(&mut key_reader, &nonce, &key);
            out.extend(header);
            out.extend(keys);

            #[cfg(feature = "multi-thread")]
            let encrypted_content = receiver.recv().unwrap()?;
            #[cfg(not(feature = "multi-thread"))]
            let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content)?;

            out.extend(encrypted_content);

            out.push(if key_reader.dh_priv_key.is_some() {
                6
            } else {
                5
            });

            Ok((out, key.into()))
        }
    }
}

/// facilitates mode-specific decryption component extraction.
#[derive(Debug)]
pub enum Components {
    Session(
        /// optional encrypted key
        Option<[u8; KEY_SIZE]>,
    ),
    Hmac(
        /// iteration
        usize,
    ),
    Dh(
        /// encrypted key
        [u8; KEY_SIZE],
        /// whether it was used with HMAC
        bool,
    ),
    Kem(
        /// encrypted key
        [u8; KEY_SIZE],
        /// KEM ciphertext
        [u8; KEM_CIPHERTEXT_SIZE],
        /// whether it was Dh hybrid
        bool,
    ),
}

/// extract components from encrypted result.
///
/// ```rust
/// # use rgp::{encrypt, generate_dh_keys, generate_fingerprint, Encrypt};
/// # let (fingerprint, verifier) = generate_fingerprint();
/// # let (session_key, _) = generate_dh_keys();
/// # let content = vec![0u8; 1024];
/// # let (encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Session(session_key, false)).unwrap();
/// #
/// use rgp::{extract_components, Components};
///
/// let (components, encrypted_content) = extract_components(0, encrypted_content);
///
/// match components {
///     Components::Session(encrypted_key) => { /* decrypt for session */ }
///     Components::Hmac(itr) => { /* decrypt for HMAC */ }
///     Components::Dh(encrypted_key, with_hmac) => { /* decrypt for diffie-hellman */ }
///     Components::Kem(encrypted_key, ciphertext, is_hybrid) => { /* decrypt for KEM */ }
/// };
/// ```
#[inline(always)]
pub fn extract_components(
    position: usize,
    mut encrypted_content: Vec<u8>,
) -> (Components, Vec<u8>) {
    let mode_meta = extract_components_mut(position, &mut encrypted_content);

    (mode_meta, encrypted_content)
}

/// extract components from encrypted result, mutating the content passed in.
///
/// ```rust
/// # use rgp::{encrypt, generate_dh_keys, generate_fingerprint, Encrypt};
/// # let (fingerprint, verifier) = generate_fingerprint();
/// # let (session_key, _) = generate_dh_keys();
/// # let content = vec![0u8; 1024];
/// # let (mut encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Session(session_key, false)).unwrap();
/// #
/// use rgp::{extract_components_mut, Components};
///
/// match extract_components_mut(0, &mut encrypted_content) {
///     Components::Session(encrypted_key) => { /* decrypt for session */ }
///     Components::Hmac(itr) => { /* decrypt for HMAC */ }
///     Components::Dh(encrypted_key, with_hmac) => { /* decrypt for diffie-hellman */ }
///     Components::Kem(encrypted_key, ciphertext, is_hybrid) => { /* decrypt for KEM */ }
/// };
/// ```
pub fn extract_components_mut(position: usize, encrypted_content: &mut Vec<u8>) -> Components {
    let mode = encrypted_content.pop().expect("at least one element");

    match mode {
        // Hmac
        1 => {
            let (itr_size, itr) = bytes_to_usize(&encrypted_content[NONCE_SIZE..NONCE_SIZE + 9]);

            encrypted_content.copy_within(NONCE_SIZE + itr_size.., NONCE_SIZE);
            encrypted_content.truncate(encrypted_content.len() - itr_size);

            Components::Hmac(itr)
        }
        // Session with key gen
        3 => {
            let encrypted_key: [u8; KEY_SIZE] = encrypted_content
                [NONCE_SIZE..NONCE_SIZE + KEY_SIZE]
                .try_into()
                .unwrap();

            encrypted_content.copy_within(NONCE_SIZE + KEY_SIZE.., NONCE_SIZE);
            encrypted_content.truncate(encrypted_content.len() - KEY_SIZE);

            Components::Session(Some(encrypted_key))
        }
        // Dh | Dh with HMAC
        2 | 4 => {
            let (keys_count_size, keys_count) =
                bytes_to_usize(&encrypted_content[NONCE_SIZE..NONCE_SIZE + 9]);

            let keys_start = NONCE_SIZE + keys_count_size;
            let encrypted_key_start = keys_start + (position as usize * KEY_SIZE);

            let content_key: [u8; KEY_SIZE] = encrypted_content
                [encrypted_key_start..encrypted_key_start + KEY_SIZE]
                .try_into()
                .unwrap();

            let encrypted_content_start = keys_start + (keys_count * KEY_SIZE);

            encrypted_content.copy_within(encrypted_content_start.., NONCE_SIZE);
            encrypted_content
                .truncate(encrypted_content.len() - keys_count_size - (keys_count * KEY_SIZE));

            Components::Dh(content_key, mode == 3)
        }
        // Kem
        5 | 6 => {
            let (keys_count_size, keys_count) =
                bytes_to_usize(&encrypted_content[NONCE_SIZE..NONCE_SIZE + 9]);

            let keys_start = NONCE_SIZE + keys_count_size;
            let encrypted_key_start =
                keys_start + (position as usize * (KEY_SIZE + KEM_CIPHERTEXT_SIZE));

            let content_key: [u8; KEY_SIZE] = encrypted_content
                [encrypted_key_start..encrypted_key_start + KEY_SIZE]
                .try_into()
                .unwrap();

            let ciphertext: [u8; KEM_CIPHERTEXT_SIZE] = encrypted_content[encrypted_key_start
                + KEY_SIZE
                ..encrypted_key_start + (KEY_SIZE + KEM_CIPHERTEXT_SIZE)]
                .try_into()
                .unwrap();

            let encrypted_content_start =
                keys_start + (keys_count * (KEY_SIZE + KEM_CIPHERTEXT_SIZE));

            encrypted_content.copy_within(encrypted_content_start.., NONCE_SIZE);
            encrypted_content.truncate(
                encrypted_content.len()
                    - keys_count_size
                    - (keys_count * (KEY_SIZE + KEM_CIPHERTEXT_SIZE)),
            );

            Components::Kem(content_key, ciphertext, mode == 6)
        }
        // Session
        _ => Components::Session(None),
    }
}

/// encapsulates the parameters and mode for decryption.
pub enum Decrypt {
    /// generates shared secret to decrypt content key.
    Dh(
        /// encrypted content key
        [u8; KEY_SIZE],
        /// sender pub key
        [u8; KEY_SIZE],
        /// recipient priv key
        [u8; KEY_SIZE],
        /// HMAC key
        Option<[u8; KEY_SIZE]>,
    ),

    /// hashes the second tuple member, with the first
    /// tuple member as the hash key.
    Hmac(
        /// HMAC key
        [u8; KEY_SIZE],
        /// HMAC value
        [u8; KEY_SIZE],
    ),

    /// uses the key that is passed in without modification.
    Session(
        /// session key
        [u8; KEY_SIZE],
        /// optional encrypted key
        Option<[u8; KEY_SIZE]>,
    ),

    /// decapsulate ciphertext to decrypt content key.
    Kem(
        /// encrypted key
        [u8; KEY_SIZE],
        /// KEM ciphertext
        [u8; KEM_CIPHERTEXT_SIZE],
        /// KEM secret key
        [u8; KEM_SECRET_KEY_SIZE],
        /// optional Dh sender pub key, and recipient priv key
        Option<([u8; KEY_SIZE], [u8; KEY_SIZE])>,
    ),
}

/// decrypts and verifies content.
///
/// ```rust
/// # use rgp::{encrypt, generate_dh_keys, generate_fingerprint, generate_kem_keys, Encrypt};
/// # let (sender_priv_key, sender_pub_key) = generate_dh_keys();
/// # let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();
/// # let (hmac_key, hmac_value) = generate_dh_keys();
/// # let (session_key, _) = generate_dh_keys();
/// # let (kem_secret_key, kem_pub_key) = generate_kem_keys();
/// # let (fingerprint, verifier) = generate_fingerprint();
/// # let content = vec![0u8; 1024];
/// # let pub_keys = vec![receiver_pub_key];
/// # let (mut encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Dh(sender_priv_key, &pub_keys, None)).unwrap();
/// #
/// use rgp::{decrypt, extract_components_mut, Components, Decrypt};
///
/// match extract_components_mut(0, &mut encrypted_content) {
///     Components::Dh(encrypted_key, with_hmac) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Dh(encrypted_key, sender_pub_key, receiver_priv_key, None),
///         ).unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
///     Components::Hmac(itr) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Hmac(hmac_key, hmac_value),
///         ).unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
///     Components::Session(encrypted_key) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Session(session_key, encrypted_key),
///         ).unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
///     Components::Kem(encrypted_key, ciphertext, is_hybrid) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Kem(encrypted_key, ciphertext, kem_secret_key, None),
///         ).unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
/// };
/// ```
pub fn decrypt(
    verifier: Option<&[u8; 32]>,
    encrypted_content: &[u8],
    mode: Decrypt,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = &GenericArray::<u8, typenum::U24>::from_slice(&encrypted_content[0..NONCE_SIZE]);

    let (content_key, encrypted_content): (GenericArray<u8, typenum::U32>, &[u8]) = match mode {
        Decrypt::Session(session_key, encrypted_key) => {
            if let Some(mut encrypted_key) = encrypted_key {
                let mut key_cipher = {
                    use chacha20::cipher::KeyIvInit;
                    XChaCha20::new(&session_key.into(), nonce)
                };

                key_cipher.apply_keystream(&mut encrypted_key);

                (encrypted_key.into(), &encrypted_content[NONCE_SIZE..])
            } else {
                (session_key.into(), &encrypted_content[NONCE_SIZE..])
            }
        }
        Decrypt::Hmac(hash_key, key) => {
            let key = blake2::Blake2sMac256::new_from_slice(&hash_key)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();

            (key, &encrypted_content[NONCE_SIZE..])
        }
        Decrypt::Dh(mut encrypted_key, pub_key, priv_key, hmac_key) => {
            let priv_key = StaticSecret::from(priv_key);
            let mut key = GenericArray::from(priv_key.diffie_hellman(&pub_key.into()).to_bytes());

            if let Some(hmac_key) = hmac_key {
                key = blake2::Blake2sMac256::new_from_slice(&hmac_key)
                    .unwrap()
                    .chain_update(&key)
                    .finalize_fixed()
            }

            let mut key_cipher = {
                use chacha20::cipher::KeyIvInit;
                XChaCha20::new(&key, nonce)
            };

            key_cipher.apply_keystream(&mut encrypted_key);

            (encrypted_key.into(), &encrypted_content[NONCE_SIZE..])
        }
        Decrypt::Kem(mut encrypted_key, ciphertext, mut secret_key, dh_components) => {
            let secret_key = KemSecretKey::from(&mut secret_key);
            let ciphertext = Ciphertext::from(ciphertext);

            let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
            let mut key = GenericArray::from(
                *decapsulate(&ciphertext, &secret_key, &mut kem_shared_secret_buf).as_array(),
            );

            if let Some((pub_key, priv_key)) = dh_components {
                let priv_key = StaticSecret::from(priv_key);
                let shared_secret = priv_key.diffie_hellman(&pub_key.into()).to_bytes();

                // HMAC the KEM shared secret with the Diffie-Hellman shared secret
                key = blake2::Blake2sMac256::new_from_slice(&shared_secret)
                    .unwrap()
                    .chain_update(&key)
                    .finalize_fixed();
            }

            let mut key_cipher = {
                use chacha20::cipher::KeyIvInit;
                XChaCha20::new(&key, nonce)
            };

            key_cipher.apply_keystream(&mut encrypted_key);

            (encrypted_key.into(), &encrypted_content[NONCE_SIZE..])
        }
    };

    let content_cipher = {
        use chacha20poly1305::KeyInit;
        XChaCha20Poly1305::new(&content_key)
    };

    match content_cipher.decrypt(nonce, encrypted_content) {
        Ok(mut content) => {
            let signature = content.split_off(content.len() - SIGNATURE_SIZE);

            match verifier {
                Some(verifier) => {
                    let signature_as_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
                        Ok(v) => v,
                        Err(_) => return Err("failed to convert signature to bytes"),
                    };

                    verify(&signature_as_bytes, verifier, &content)?;
                    Ok((content, content_key.into()))
                }
                None => Ok((content, content_key.into())),
            }
        }
        Err(_) => return Err("failed to decrypt content"),
    }
}
