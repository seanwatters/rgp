/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

#![doc = include_str!("../README.md")]

use std::sync::mpsc::channel;

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

/// for generating fingerprints for signatures.
///
/// ```rust
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
///
/// let signature = rgp::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = rgp::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
    let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    (
        fingerprint.to_bytes(),
        fingerprint.verifying_key().to_bytes(),
    )
}

/// for signing content.
///
/// ```rust
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
///
/// let signature = rgp::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = rgp::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
#[inline]
pub fn sign(fingerprint: &[u8; 32], content: &[u8]) -> [u8; 64] {
    let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
    let signature = fingerprint.sign(content);

    signature.to_bytes()
}

/// for verifying signatures.
///
/// ```rust
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
///
/// let signature = rgp::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = rgp::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
#[inline]
pub fn verify(
    signature: &[u8; 64],
    verifying_key: &[u8; 32],
    content: &[u8],
) -> Result<(), &'static str> {
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(verifying_key) {
        Ok(vk) => vk,
        Err(_) => return Err("failed to convert verifying key"),
    };

    match verifying_key.verify(content, &signature) {
        Ok(_) => Ok(()),
        Err(_) => return Err("failed to verify signature"),
    }
}

/// for generating pub/priv key pairs.
///
/// ```rust
/// let (priv_key, pub_key) = rgp::generate_dh_keys();
///
/// assert_eq!(priv_key.len(), 32);
/// assert_eq!(pub_key.len(), 32);
/// ```
pub fn generate_dh_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

#[inline]
fn gen_keys_header(key_count: usize) -> Vec<u8> {
    match key_count {
        0..=63 => vec![(0 << 6) | key_count as u8],
        64..=318 => vec![((0 << 6) | 63), (key_count - 63) as u8],
        319..=65_598 => {
            let mut h = vec![(1 << 6) | 63];
            h.extend_from_slice(&((key_count - 63) as u16).to_be_bytes());
            h
        }
        65_599..=4_294_967_358 => {
            let mut h = vec![(2 << 6) | 63];
            h.extend_from_slice(&((key_count - 63) as u32).to_be_bytes());
            h
        }
        _ => {
            let mut h = vec![(3 << 6) | 63];
            h.extend_from_slice(&((key_count - 63) as u64).to_be_bytes());
            h
        }
    }
}

#[inline]
fn parse_keys_header(encrypted_content: &Vec<u8>) -> Result<(usize, usize), &'static str> {
    let keys_header_size = encrypted_content[NONCE_LEN];

    if keys_header_size < 64 {
        Ok((1, keys_header_size as usize))
    } else {
        let out = match (keys_header_size >> 6) & 0b11 {
            0 => (2, encrypted_content[NONCE_LEN + 1] as usize + 63),
            1 => (
                3,
                u16::from_be_bytes(
                    encrypted_content[NONCE_LEN + 1..NONCE_LEN + 3]
                        .try_into()
                        .unwrap(),
                ) as usize
                    + 63,
            ),
            2 => (
                5,
                u32::from_be_bytes(
                    encrypted_content[NONCE_LEN + 1..NONCE_LEN + 5]
                        .try_into()
                        .unwrap(),
                ) as usize
                    + 63,
            ),
            3 => (
                9,
                u64::from_be_bytes(
                    encrypted_content[NONCE_LEN + 1..NONCE_LEN + 9]
                        .try_into()
                        .unwrap(),
                ) as usize
                    + 63,
            ),
            _ => return Err("unknown keys header value"),
        };

        Ok(out)
    }
}

#[inline]
fn encrypt_content(
    fingerprint: [u8; 32],
    nonce: &GenericArray<u8, typenum::U24>,
    key: &GenericArray<u8, typenum::U32>,
    mut content: Vec<u8>,
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
    use rayon::prelude::*;

    let keys_count = pub_keys.len();
    let header = gen_keys_header(keys_count);

    let priv_key = StaticSecret::from(priv_key);

    let mut keys = vec![0u8; KEY_LEN * keys_count];

    keys.par_chunks_mut(KEY_LEN)
        .enumerate()
        .for_each(|(i, chunk)| {
            let shared_secret = priv_key
                .diffie_hellman(&PublicKey::from(pub_keys[i]))
                .to_bytes();

            let mut key_cipher = XChaCha20::new(&shared_secret.into(), &nonce);

            let mut buf = content_key.clone();

            key_cipher.apply_keystream(&mut buf);
            chunk[0..KEY_LEN].copy_from_slice(&buf);
        });

    (header, keys)
}

/// specifies how the content key should be handled for encryption.
pub enum EncryptMode<'a> {
    /// generates random content key and encrypts for all
    /// recipients with their respective DH shared secret.
    Dh([u8; KEY_LEN], &'a Vec<[u8; KEY_LEN]>),

    /// hashes the second tuple member, with the first
    /// tuple member as the hash key.
    Hash([u8; KEY_LEN], [u8; KEY_LEN]),

    /// uses the key that is passed in without modification.
    Session([u8; KEY_LEN]),
}

/// content encryption.
///
/// ```rust
/// let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();
/// let (receiver_priv_key, receiver_pub_key) = rgp::generate_dh_keys();
///
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1_000_000];
/// let pub_keys = vec![receiver_pub_key];
///
/// let (mut encrypted_content, _) =
///     rgp::encrypt(fingerprint, content.clone(), rgp::EncryptMode::Dh(sender_priv_key, &pub_keys)).unwrap();
///
/// rgp::extract_for_dh_key_position_mut(0, &mut encrypted_content).unwrap();
///
/// let decrypted_content = rgp::decrypt(
///     Some(&verifying_key),
///     sender_pub_key,
///     receiver_priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub fn encrypt(
    fingerprint: [u8; 32],
    content: Vec<u8>,
    mode: EncryptMode,
) -> Result<(Vec<u8>, [u8; KEY_LEN]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    match mode {
        EncryptMode::Session(key) => {
            // out.push(0);

            let encrypted_content = encrypt_content(fingerprint, &nonce, &key.into(), content)?;
            out.extend(encrypted_content);

            Ok((out, key))
        }
        EncryptMode::Hash(hash_key, last_key) => {
            // out.push(1);

            use blake2::digest::{FixedOutput, Mac};

            let key = blake2::Blake2sMac256::new_from_slice(&hash_key)
                .unwrap()
                .chain_update(&last_key)
                .finalize_fixed();

            let encrypted_content = encrypt_content(fingerprint, &nonce, &key, content)?;
            out.extend(encrypted_content);

            Ok((out, key.into()))
        }
        EncryptMode::Dh(priv_key, pub_keys) => {
            // out.push(2);

            use chacha20poly1305::KeyInit;
            let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

            let (sender, receiver) = channel();

            rayon::spawn(move || {
                let encrypted_content = encrypt_content(fingerprint, &nonce, &key, content);
                sender.send(encrypted_content).unwrap();
            });

            let (header, keys) = dh_encrypt_keys(priv_key, pub_keys, &nonce, &key);
            out.extend(header);
            out.extend(keys);

            let encrypted_content = receiver.recv().unwrap()?;
            out.extend(encrypted_content);

            Ok((out, key.into()))
        }
    }
}

/// extract components from encrypted result.
///
/// ```rust
/// let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();
/// let (receiver_priv_key, receiver_pub_key) = rgp::generate_dh_keys();
///
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1_000_000];
/// let pub_keys = vec![receiver_pub_key];
///
/// let (encrypted_content, _) =
///     rgp::encrypt(fingerprint, content.clone(), rgp::EncryptMode::Dh(sender_priv_key, &pub_keys)).unwrap();
///
/// let encrypted_content = rgp::extract_for_dh_key_position(0, encrypted_content).unwrap();
///
/// let decrypted_content = rgp::decrypt(
///     Some(&verifying_key),
///     sender_pub_key,
///     receiver_priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub fn extract_for_dh_key_position(
    position: usize,
    mut encrypted_content: Vec<u8>,
) -> Result<Vec<u8>, &'static str> {
    let (keys_header_len, keys_count) = parse_keys_header(&encrypted_content)?;

    let keys_start = NONCE_LEN + keys_header_len;
    let encrypted_key_start = keys_start + (position as usize * KEY_LEN);

    let encrypted_content_start = keys_start + (keys_count * KEY_LEN);

    encrypted_content.copy_within(
        encrypted_key_start..encrypted_key_start + KEY_LEN,
        NONCE_LEN,
    );
    encrypted_content.copy_within(encrypted_content_start.., NONCE_LEN + KEY_LEN);
    encrypted_content
        .truncate(encrypted_content.len() - keys_header_len - ((keys_count - 1) * KEY_LEN));

    Ok(encrypted_content)
}

/// extract components from encrypted result, mutating the content passed in.
///
/// ```rust
/// let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();
/// let (receiver_priv_key, receiver_pub_key) = rgp::generate_dh_keys();
///
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1_000_000];
/// let pub_keys = vec![receiver_pub_key];
///
/// let (mut encrypted_content, _) =
///     rgp::encrypt(fingerprint, content.clone(), rgp::EncryptMode::Dh(sender_priv_key, &pub_keys)).unwrap();
///
/// rgp::extract_for_dh_key_position_mut(0, &mut encrypted_content).unwrap();
///
/// let decrypted_content = rgp::decrypt(
///     Some(&verifying_key),
///     sender_pub_key,
///     receiver_priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub fn extract_for_dh_key_position_mut(
    position: usize,
    encrypted_content: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let (keys_header_len, keys_count) = parse_keys_header(encrypted_content)?;

    let keys_start = NONCE_LEN + keys_header_len;
    let encrypted_key_start = keys_start + (position as usize * KEY_LEN);

    let encrypted_content_start = keys_start + (keys_count * KEY_LEN);

    encrypted_content.copy_within(
        encrypted_key_start..encrypted_key_start + KEY_LEN,
        NONCE_LEN,
    );
    encrypted_content.copy_within(encrypted_content_start.., NONCE_LEN + KEY_LEN);
    encrypted_content
        .truncate(encrypted_content.len() - keys_header_len - ((keys_count - 1) * KEY_LEN));

    Ok(())
}

/// specifies how the content key should be handled for encryption.
pub enum DecryptMode {
    /// receiver priv key and sender pub key.
    Dh([u8; KEY_LEN], [u8; KEY_LEN]),

    /// hashes the second tuple member, with the first
    /// tuple member as the hash key.
    Hash([u8; KEY_LEN], [u8; KEY_LEN]),

    /// uses the key that is passed in without modification.
    Session([u8; KEY_LEN]),
}

/// content decryption.
///
/// ```rust
/// let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();
/// let (receiver_priv_key, receiver_pub_key) = rgp::generate_dh_keys();
///
/// let (fingerprint, verifying_key) = rgp::generate_fingerprint();
///
/// let content = vec![0u8; 1_000_000];
/// let pub_keys = vec![receiver_pub_key];
///
/// let (mut encrypted_content, _) =
///     rgp::encrypt(fingerprint, content.clone(), rgp::EncryptMode::Dh(sender_priv_key, &pub_keys)).unwrap();
///
/// rgp::extract_for_dh_key_position_mut(0, &mut encrypted_content).unwrap();
///
/// let decrypted_content = rgp::decrypt(
///     Some(&verifying_key),
///     sender_pub_key,
///     receiver_priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub fn decrypt(
    verifying_key: Option<&[u8; 32]>,
    pub_key: [u8; KEY_LEN],
    priv_key: [u8; KEY_LEN],
    encrypted_content: &[u8],
    // mode: DecryptMode,
) -> Result<Vec<u8>, &'static str> {
    let nonce: [u8; NONCE_LEN] = match encrypted_content[0..NONCE_LEN].try_into() {
        Ok(key) => key,
        Err(_) => return Err("failed to convert nonce to bytes"),
    };

    let mut content_key = encrypted_content[NONCE_LEN..NONCE_LEN + KEY_LEN].to_vec();

    let priv_key = StaticSecret::from(priv_key);
    let shared_secret = priv_key.diffie_hellman(&pub_key.into()).to_bytes();

    let mut key_cipher = {
        use chacha20::cipher::KeyIvInit;
        XChaCha20::new(&shared_secret.into(), &nonce.into())
    };

    key_cipher.apply_keystream(&mut content_key);

    let content_key: [u8; KEY_LEN] = match content_key.try_into() {
        Ok(key_bytes) => key_bytes,
        Err(_) => return Err("failed to convert content key to bytes"),
    };

    let content_cipher = {
        use chacha20poly1305::KeyInit;
        XChaCha20Poly1305::new(&content_key.into())
    };

    match content_cipher.decrypt(&nonce.into(), &encrypted_content[NONCE_LEN + KEY_LEN..]) {
        Ok(mut content) => {
            let signature = content.split_off(content.len() - SIGNATURE_LEN);

            match verifying_key {
                Some(verifying_key) => {
                    let signature_as_bytes: [u8; SIGNATURE_LEN] = match signature.try_into() {
                        Ok(v) => v,
                        Err(_) => return Err("failed to convert signature to bytes"),
                    };

                    verify(&signature_as_bytes, verifying_key, &content)?;
                    Ok(content)
                }
                None => Ok(content),
            }
        }
        Err(_) => return Err("failed to decrypt content"),
    }
}
