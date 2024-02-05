/*
ordinal_crypto is the cryptography library for the Ordinal Platform

Copyright (C) 2024 sean watters

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#![doc = include_str!("../README.md")]

/// for converting any string into 32 bytes.
///
/// ```rust
/// let as_bytes = ordinal_crypto::hash_str("make me bytes");
///
/// assert_eq!(as_bytes, [140, 80, 144, 129, 175, 43, 30, 228, 156, 242, 68, 212, 88, 54, 57, 61, 153, 171, 132, 241, 152, 87, 192, 17, 182, 131, 148, 93, 31, 156, 227, 133]);
///```
pub fn hash_str(val: &str) -> [u8; 32] {
    use blake2::Digest;

    let mut hasher = blake2::Blake2s256::new();
    hasher.update(val.as_bytes());
    let res = hasher.finalize();

    let mut out = [0u8; 32];
    out[0..32].copy_from_slice(&res);

    out
}

/// for converting 32 byte keys to/from strings.
///
/// ```rust
/// let key = [0u8; 32];
///
/// let key_str = ordinal_crypto::bytes_32::encode(&key);
///
/// assert_eq!(key_str, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
///
/// let decoded_key = ordinal_crypto::bytes_32::decode(&key_str).unwrap();
///
/// assert_eq!(decoded_key, key);
///```
pub mod bytes_32 {
    use base64::{engine::general_purpose::STANDARD as b64, Engine};

    pub fn encode(val: &[u8; 32]) -> String {
        b64.encode(val)
    }

    pub fn decode(val: &str) -> Result<[u8; 32], &'static str> {
        let decoded_val = match b64.decode(val) {
            Ok(val) => val,
            Err(_) => return Err("failed to decode val"),
        };

        let decoded_val_as_bytes: [u8; 32] = match decoded_val.try_into() {
            Ok(val) => val,
            Err(_) => return Err("failed to convert decoded val into fixed bytes"),
        };

        Ok(decoded_val_as_bytes)
    }
}

/// for signing/verifying content and request payloads.
///
/// ```rust
/// let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
///
/// let signature = ordinal_crypto::signature::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = ordinal_crypto::signature::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
pub mod signature {
    use ed25519_dalek::{Signer, Verifier};

    pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
        let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        // TODO: zeroize
        (
            fingerprint.to_bytes(),
            fingerprint.verifying_key().to_bytes(),
        )
    }

    pub fn sign(fingerprint: &[u8; 32], content: &[u8]) -> [u8; 64] {
        let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
        let signature = fingerprint.sign(content);

        signature.to_bytes()
    }

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
}

/// for generating pub/priv keys which are used for DH.
///
/// ```rust
/// let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
///
/// assert_eq!(priv_key.len(), 32);
/// assert_eq!(pub_key.len(), 32);
/// ```
pub fn generate_exchange_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    // TODO: zeroize
    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

/// core encryption/signing logic for payloads.
///
/// ```rust
/// let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
/// let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
/// let pub_keys = vec![pub_key];
///
/// let mut encrypted_content =
///     ordinal_crypto::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();
///
/// let encrypted_content =
///     ordinal_crypto::content::extract_content_for_key_position(&mut encrypted_content, 0)
///         .unwrap();
///
/// let decrypted_content = ordinal_crypto::content::decrypt(
///     Some(&verifying_key),
///     priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub mod content {
    use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
    use rayon::prelude::*;
    use std::thread;

    const NONCE_LEN: usize = 24;
    const MAC_LEN: usize = 16;
    const KEY_LEN: usize = 32;
    const ENCRYPTED_KEY_LEN: usize = KEY_LEN + MAC_LEN;
    const SIGNATURE_LEN: usize = 64;
    const ENCRYPTED_KEY_WITH_NONCE_LEN: usize = NONCE_LEN + ENCRYPTED_KEY_LEN;

    pub fn encrypt(
        fingerprint: [u8; 32],
        mut content: Vec<u8>,
        pub_keys: &Vec<[u8; KEY_LEN]>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut out = vec![];

        // generate components
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
        let content_key = chacha20poly1305::XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

        let e_priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let ot_pub_key = x25519_dalek::PublicKey::from(&e_priv_key);

        out.extend(&nonce);
        out.extend(ot_pub_key.as_bytes());

        // create keys header
        let pub_key_count = pub_keys.len();
        let keys_header = match pub_key_count {
            0..=255 => vec![1, pub_key_count as u8],
            256..=65_535 => {
                let mut h = vec![2];
                h.extend_from_slice(&(pub_key_count as u16).to_be_bytes());
                h
            }
            65_536..=4_294_967_295 => {
                let mut h = vec![4];
                h.extend_from_slice(&(pub_key_count as u32).to_be_bytes());
                h
            }
            _ => {
                let mut h = vec![8];
                h.extend_from_slice(&(pub_key_count as u64).to_be_bytes());
                h
            }
        };

        out.extend(&keys_header);

        // sign/encrypt content
        let sign_and_encrypt_handle = thread::spawn(move || {
            let signature = super::signature::sign(&fingerprint, &content);
            content.extend(signature);

            let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&content_key);
            match content_cipher.encrypt(&nonce, content.as_ref()) {
                Ok(encrypted_content) => return Ok(encrypted_content),
                Err(_) => return Err("failed to encrypt content"),
            }
        });

        let mut encrypted_keys = vec![0u8; ENCRYPTED_KEY_WITH_NONCE_LEN * pub_key_count];

        // encrypt keys
        encrypted_keys
            .par_chunks_mut(ENCRYPTED_KEY_WITH_NONCE_LEN)
            .enumerate()
            .for_each(|(i, chunk)| {
                let shared_secret = e_priv_key
                    .diffie_hellman(&x25519_dalek::PublicKey::from(pub_keys[i]))
                    .to_bytes();

                let key_cipher = chacha20poly1305::XChaCha20Poly1305::new(&shared_secret.into());
                let key_nonce =
                    chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
                let encrypted_content_key = key_cipher
                    .encrypt(&key_nonce, content_key.as_ref())
                    .expect("failed to encrypt key");

                chunk[0..NONCE_LEN].copy_from_slice(&key_nonce);
                chunk[NONCE_LEN..ENCRYPTED_KEY_WITH_NONCE_LEN]
                    .copy_from_slice(&encrypted_content_key);
            });

        out.extend(encrypted_keys);

        let encrypted_content = sign_and_encrypt_handle.join().unwrap()?;
        out.extend(encrypted_content);

        Ok(out)
    }

    pub fn extract_content_for_key_position(
        encrypted_content: &mut Vec<u8>,
        position: u16,
    ) -> Result<&[u8], &'static str> {
        let ot_pub_key_start = NONCE_LEN;
        let keys_header_start = ot_pub_key_start + KEY_LEN;

        let (keys_header_len, keys_count): (usize, usize) =
            match encrypted_content[keys_header_start] {
                1 => (2, encrypted_content[keys_header_start + 1] as usize),
                2 => (
                    3,
                    u16::from_be_bytes(
                        encrypted_content[keys_header_start + 1..keys_header_start + 3]
                            .try_into()
                            .unwrap(),
                    ) as usize,
                ),
                4 => (
                    5,
                    u32::from_be_bytes(
                        encrypted_content[keys_header_start + 1..keys_header_start + 5]
                            .try_into()
                            .unwrap(),
                    ) as usize,
                ),
                8 => (
                    9,
                    u64::from_be_bytes(
                        encrypted_content[keys_header_start + 1..keys_header_start + 9]
                            .try_into()
                            .unwrap(),
                    ) as usize,
                ),
                _ => return Err("unknown keys header value"),
            };

        let keys_start = keys_header_start + keys_header_len;
        let encrypted_key_start = keys_start + (position as usize * ENCRYPTED_KEY_WITH_NONCE_LEN);

        let encrypted_content_start = keys_start + (keys_count * ENCRYPTED_KEY_WITH_NONCE_LEN);

        encrypted_content
            .drain(encrypted_key_start + ENCRYPTED_KEY_WITH_NONCE_LEN..encrypted_content_start);
        encrypted_content.drain(keys_header_start..encrypted_key_start);

        Ok(encrypted_content)
    }

    pub fn decrypt(
        verifying_key: Option<&[u8; 32]>,
        priv_key: [u8; KEY_LEN],
        encrypted_content: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let content_nonce: [u8; NONCE_LEN] = match encrypted_content[0..NONCE_LEN].try_into() {
            Ok(key) => key,
            Err(_) => return Err("failed to convert nonce to bytes"),
        };

        let ot_pub_key: [u8; KEY_LEN] =
            match encrypted_content[NONCE_LEN..NONCE_LEN + KEY_LEN].try_into() {
                Ok(key) => key,
                Err(_) => return Err("failed to convert pub key to bytes"),
            };

        let encrypted_key: [u8; ENCRYPTED_KEY_WITH_NONCE_LEN] = match encrypted_content
            [NONCE_LEN + KEY_LEN..NONCE_LEN + KEY_LEN + ENCRYPTED_KEY_WITH_NONCE_LEN]
            .try_into()
        {
            Ok(key) => key,
            Err(_) => return Err("failed to convert encrypted key to bytes"),
        };

        let priv_key = x25519_dalek::StaticSecret::from(priv_key);
        let shared_secret = priv_key.diffie_hellman(&ot_pub_key.into()).to_bytes();

        let key_cipher = chacha20poly1305::XChaCha20Poly1305::new(&shared_secret.into());
        let key_nonce: [u8; NONCE_LEN] = match encrypted_key[0..NONCE_LEN].try_into() {
            Ok(n) => n,
            Err(_) => return Err("failed to convert key nonce into bytes"),
        };

        let content_key: [u8; KEY_LEN] =
            match key_cipher.decrypt(&key_nonce.into(), &encrypted_key[NONCE_LEN..]) {
                Ok(ck) => match ck[0..KEY_LEN].try_into() {
                    Ok(key_bytes) => key_bytes,
                    Err(_) => return Err("failed to convert content key to bytes"),
                },
                Err(_) => return Err("failed to decrypt content key"),
            };

        let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&content_key.into());

        match content_cipher.decrypt(
            &content_nonce.into(),
            &encrypted_content[NONCE_LEN + KEY_LEN + ENCRYPTED_KEY_WITH_NONCE_LEN..],
        ) {
            Ok(mut content) => {
                let signature = content.split_off(content.len() - SIGNATURE_LEN);

                match verifying_key {
                    Some(verifying_key) => {
                        let signature_as_bytes: [u8; SIGNATURE_LEN] = match signature.try_into() {
                            Ok(v) => v,
                            Err(_) => return Err("failed to convert signature to bytes"),
                        };

                        super::signature::verify(&signature_as_bytes, verifying_key, &content)?;
                        Ok(content)
                    }
                    None => Ok(content),
                }
            }
            Err(_) => return Err("failed to decrypt content"),
        }
    }
}
