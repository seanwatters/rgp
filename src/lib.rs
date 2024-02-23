/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

#![doc = include_str!("../README.md")]

mod interaction;

#[cfg(feature = "multi-thread")]
use rayon::prelude::*;
#[cfg(feature = "multi-thread")]
use std::sync::mpsc::channel;

use blake2::digest::{FixedOutput, Mac};
use chacha20::{
    cipher::{generic_array::GenericArray, typenum, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::{aead::Aead, AeadCore, XChaCha20Poly1305};
use ed25519_dalek::{Signer, Verifier};
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

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
    priv_key: [u8; KEY_LEN],
    pub_keys: &Vec<[u8; KEY_LEN]>,
    nonce: &GenericArray<u8, typenum::U24>,
    content_key: &GenericArray<u8, typenum::U32>,
) -> (Vec<u8>, Vec<u8>) {
    use chacha20::cipher::KeyIvInit;

    let keys_count = pub_keys.len();
    let header = usize_to_bytes(keys_count);

    let priv_key = StaticSecret::from(priv_key);

    let mut keys = vec![0u8; KEY_LEN * keys_count];

    #[cfg(feature = "multi-thread")]
    let chunks = keys.par_chunks_mut(KEY_LEN);
    #[cfg(not(feature = "multi-thread"))]
    let chunks = keys.chunks_mut(KEY_LEN);

    chunks.enumerate().for_each(|(i, chunk)| {
        let shared_secret = priv_key
            .diffie_hellman(&PublicKey::from(pub_keys[i]))
            .to_bytes();

        let mut key_cipher = XChaCha20::new(&shared_secret.into(), nonce);

        let mut buf = content_key.clone();

        key_cipher.apply_keystream(&mut buf);
        chunk[0..KEY_LEN].copy_from_slice(&buf);
    });

    (header, keys)
}

/// encapsulates the parameters and mode for encryption.
pub enum Encrypt<'a> {
    /// generates random content key and encrypts for all
    /// recipients with their respective DH shared secret.
    Dh([u8; KEY_LEN], &'a Vec<[u8; KEY_LEN]>),

    /// hashes the second tuple member, with the first
    /// tuple member as the hash key.
    Hmac([u8; KEY_LEN], [u8; KEY_LEN], usize),

    /// uses the key that is passed in without modification.
    Session([u8; KEY_LEN]),
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
///     Encrypt::Dh(sender_priv_key, &recipient_pub_keys)
/// ).unwrap();
/// # if let Components::Dh(content_key) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Dh(content_key, sender_pub_key, receiver_priv_key),
/// #     )
/// #     .unwrap();
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
/// #     )
/// #     .unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
///
/// // Session
/// # let content = content_clone.clone();
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     Encrypt::Session(session_key)
/// ).unwrap();
/// # if let Components::Session = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Session(session_key),
/// #     )
/// #     .unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
/// ```
pub fn encrypt(
    fingerprint: [u8; 32],
    mut content: Vec<u8>,
    mode: Encrypt,
) -> Result<(Vec<u8>, [u8; KEY_LEN]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    match mode {
        Encrypt::Session(key) => {
            let encrypted_content =
                encrypt_content(fingerprint, &nonce, &key.into(), &mut content)?;
            out.extend(encrypted_content);

            out.push(0);

            Ok((out, key))
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
        Encrypt::Dh(priv_key, pub_keys) => {
            use chacha20poly1305::KeyInit;

            let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

            #[cfg(feature = "multi-thread")]
            let (sender, receiver) = channel();

            #[cfg(feature = "multi-thread")]
            rayon::spawn(move || {
                let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content);
                sender.send(encrypted_content).unwrap();
            });

            let (header, keys) = dh_encrypt_keys(priv_key, pub_keys, &nonce, &key);
            out.extend(header);
            out.extend(keys);

            #[cfg(feature = "multi-thread")]
            let encrypted_content = receiver.recv().unwrap()?;
            #[cfg(not(feature = "multi-thread"))]
            let encrypted_content = encrypt_content(fingerprint, &nonce, &key, &mut content)?;

            out.extend(encrypted_content);

            out.push(2);

            Ok((out, key.into()))
        }
    }
}

/// facilitates mode-specific decryption component extraction.
pub enum Components {
    Session,
    Hmac(usize),
    Dh([u8; KEY_LEN]),
}

/// extract components from encrypted result.
///
/// ```rust
/// # use rgp::{encrypt, generate_dh_keys, generate_fingerprint, Encrypt};
/// # let (fingerprint, verifier) = generate_fingerprint();
/// # let (session_key, _) = generate_dh_keys();
/// # let content = vec![0u8; 1024];
/// # let (encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Session(session_key)).unwrap();
/// #
/// use rgp::{extract_components, Components};
///
/// let (components, encrypted_content) = extract_components(0, encrypted_content);
///
/// match components {
///     Components::Session => { /* decrypt for session */ }
///     Components::Hmac(itr) => { /* decrypt for HMAC */ }
///     Components::Dh(key) => { /* decrypt for diffie-hellman */ }
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
/// # let (mut encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Session(session_key)).unwrap();
/// #
/// use rgp::{extract_components_mut, Components};
///
/// match extract_components_mut(0, &mut encrypted_content) {
///     Components::Session => { /* decrypt for session */ }
///     Components::Hmac(itr) => { /* decrypt for HMAC */ }
///     Components::Dh(key) => { /* decrypt for diffie-hellman */ }
/// };
/// ```
pub fn extract_components_mut(position: usize, encrypted_content: &mut Vec<u8>) -> Components {
    let mode = encrypted_content.pop().expect("at least one element");

    match mode {
        2 => {
            let (keys_count_size, keys_count) =
                bytes_to_usize(&encrypted_content[NONCE_LEN..NONCE_LEN + 9]);

            let keys_start = NONCE_LEN + keys_count_size;
            let encrypted_key_start = keys_start + (position as usize * KEY_LEN);

            let encrypted_content_start = keys_start + (keys_count * KEY_LEN);

            let content_key: [u8; KEY_LEN] = encrypted_content
                [encrypted_key_start..encrypted_key_start + KEY_LEN]
                .try_into()
                .unwrap();

            encrypted_content.copy_within(encrypted_content_start.., NONCE_LEN);
            encrypted_content
                .truncate(encrypted_content.len() - keys_count_size - (keys_count * KEY_LEN));

            Components::Dh(content_key)
        }
        1 => {
            let (itr_size, itr) = bytes_to_usize(&encrypted_content[NONCE_LEN..NONCE_LEN + 9]);

            encrypted_content.copy_within(NONCE_LEN + itr_size.., NONCE_LEN);
            encrypted_content.truncate(encrypted_content.len() - itr_size);

            Components::Hmac(itr)
        }
        _ => Components::Session,
    }
}

/// encapsulates the parameters and mode for decryption.
pub enum Decrypt {
    /// encrypted content key, sender pub key, receiver priv key.
    Dh([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]),

    /// hashes the second tuple member, with the first
    /// tuple member as the hash key.
    Hmac([u8; KEY_LEN], [u8; KEY_LEN]),

    /// uses the key that is passed in without modification.
    Session([u8; KEY_LEN]),
}

/// decrypts and verifies content.
///
/// ```rust
/// # use rgp::{encrypt, generate_dh_keys, generate_fingerprint, Encrypt};
/// # let (sender_priv_key, sender_pub_key) = generate_dh_keys();
/// # let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();
/// # let (hmac_key, hmac_value) = generate_dh_keys();
/// # let (session_key, _) = generate_dh_keys();
/// # let (fingerprint, verifier) = generate_fingerprint();
/// # let content = vec![0u8; 1024];
/// # let pub_keys = vec![receiver_pub_key];
/// # let (mut encrypted_content, _) = encrypt(fingerprint, content.clone(), Encrypt::Dh(sender_priv_key, &pub_keys)).unwrap();
/// #
/// use rgp::{decrypt, extract_components_mut, Components, Decrypt};
///
/// match extract_components_mut(0, &mut encrypted_content) {
///     Components::Dh(key) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Dh(key, sender_pub_key, receiver_priv_key),
///         )
///         .unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
///     Components::Hmac(itr) => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Hmac(hmac_key, hmac_value),
///         )
///         .unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
///     Components::Session => {
///         let (decrypted_content, _) = decrypt(
///             Some(&verifier),
///             &encrypted_content,
///             Decrypt::Session(session_key),
///         )
///         .unwrap();
/// #       assert_eq!(decrypted_content, content);
///     }
/// };
/// ```
pub fn decrypt(
    verifier: Option<&[u8; 32]>,
    encrypted_content: &[u8],
    mode: Decrypt,
) -> Result<(Vec<u8>, [u8; KEY_LEN]), &'static str> {
    let nonce = &GenericArray::<u8, typenum::U24>::from_slice(&encrypted_content[0..NONCE_LEN]);

    let (content_key, encrypted_content): (GenericArray<u8, typenum::U32>, &[u8]) = match mode {
        Decrypt::Session(key) => (key.into(), &encrypted_content[NONCE_LEN..]),
        Decrypt::Hmac(hash_key, key) => {
            let key = blake2::Blake2sMac256::new_from_slice(&hash_key)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();

            (key, &encrypted_content[NONCE_LEN..])
        }
        Decrypt::Dh(mut content_key, pub_key, priv_key) => {
            let priv_key = StaticSecret::from(priv_key);
            let shared_secret = priv_key.diffie_hellman(&pub_key.into()).to_bytes();

            let mut key_cipher = {
                use chacha20::cipher::KeyIvInit;
                XChaCha20::new(&shared_secret.into(), nonce)
            };

            key_cipher.apply_keystream(&mut content_key);

            let content_key = GenericArray::from(content_key);

            (content_key, &encrypted_content[NONCE_LEN..])
        }
    };

    let content_cipher = {
        use chacha20poly1305::KeyInit;
        XChaCha20Poly1305::new(&content_key)
    };

    match content_cipher.decrypt(nonce, encrypted_content) {
        Ok(mut content) => {
            let signature = content.split_off(content.len() - SIGNATURE_LEN);

            match verifier {
                Some(verifier) => {
                    let signature_as_bytes: [u8; SIGNATURE_LEN] = match signature.try_into() {
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
