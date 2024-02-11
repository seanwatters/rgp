/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE-MIT or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

#![doc = include_str!("../README.md")]

mod storage;

/// for signing/verifying content.
///
/// ```rust
/// let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1215];
///
/// let signature = rgp::signature::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = rgp::signature::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
pub mod signature {
    use ed25519_dalek::{Signer, Verifier};

    pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
        let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

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

/// for generating pub/priv key pairs.
///
/// ```rust
/// let (priv_key, pub_key) = rgp::generate_exchange_keys();
///
/// assert_eq!(priv_key.len(), 32);
/// assert_eq!(pub_key.len(), 32);
/// ```
pub fn generate_exchange_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

/// content encryption/signing.
///
/// ```rust
/// let (priv_key, pub_key) = rgp::generate_exchange_keys();
/// let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1];
/// let pub_keys = vec![pub_key];
///
/// let mut encrypted_content =
///     rgp::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();
///
/// let encrypted_content =
///     rgp::content::extract_content_for_key_position(&mut encrypted_content, 0)
///         .unwrap();
///
/// let decrypted_content = rgp::content::decrypt(
///     Some(&verifying_key),
///     priv_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub mod content {
    #[cfg(feature = "multi-thread")]
    use rayon::prelude::*;
    #[cfg(feature = "multi-thread")]
    use std::thread;

    use chacha20::{cipher::StreamCipher, XChaCha20 as ChaCha};
    use chacha20poly1305::{aead::Aead, AeadCore, XChaCha20Poly1305 as ChaChaAEAD};

    use x25519_dalek::{PublicKey, StaticSecret};

    const NONCE_LEN: usize = 24;
    const KEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    pub fn encrypt(
        fingerprint: [u8; 32],
        mut content: Vec<u8>,
        pub_keys: &Vec<[u8; KEY_LEN]>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut out = vec![];

        // generate components
        let nonce = ChaChaAEAD::generate_nonce(&mut rand_core::OsRng);
        let content_key = {
            use chacha20poly1305::KeyInit;
            ChaChaAEAD::generate_key(&mut rand_core::OsRng)
        };

        // sign/encrypt content

        #[cfg(feature = "multi-thread")]
        let sign_and_encrypt_handle = thread::spawn(move || {
            use chacha20poly1305::KeyInit;

            let signature = super::signature::sign(&fingerprint, &content);
            content.extend(signature);

            let content_cipher = ChaChaAEAD::new(&content_key);
            match content_cipher.encrypt(&nonce, content.as_ref()) {
                Ok(encrypted_content) => Ok(encrypted_content),
                Err(_) => Err("failed to encrypt content"),
            }
        });

        #[cfg(not(feature = "multi-thread"))]
        let encrypted_content = {
            use chacha20poly1305::KeyInit;

            let signature = super::signature::sign(&fingerprint, &content);
            content.extend(signature);

            let content_cipher = ChaChaAEAD::new(&content_key);
            match content_cipher.encrypt(&nonce, content.as_ref()) {
                Ok(encrypted_content) => encrypted_content,
                Err(_) => return Err("failed to encrypt content"),
            }
        };

        // generate components
        let e_priv_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let ot_pub_key = PublicKey::from(&e_priv_key);

        out.extend(&nonce);
        out.extend(ot_pub_key.as_bytes());

        // create keys header
        let pub_key_count = pub_keys.len();
        let keys_header: Vec<u8> = match pub_key_count {
            0..=63 => vec![(0 << 6) | pub_key_count as u8],
            64..=318 => vec![((0 << 6) | 63), (pub_key_count - 63) as u8],
            319..=65_598 => {
                let mut h = vec![(1 << 6) | 63];
                h.extend_from_slice(&((pub_key_count - 63) as u16).to_be_bytes());
                h
            }
            65_599..=4_294_967_358 => {
                let mut h = vec![(2 << 6) | 63];
                h.extend_from_slice(&((pub_key_count - 63) as u32).to_be_bytes());
                h
            }
            _ => {
                let mut h = vec![(3 << 6) | 63];
                h.extend_from_slice(&((pub_key_count - 63) as u64).to_be_bytes());
                h
            }
        };

        out.extend(&keys_header);

        let mut encrypted_keys = vec![0u8; KEY_LEN * pub_key_count];

        // encrypt keys

        #[cfg(feature = "multi-thread")]
        encrypted_keys
            .par_chunks_mut(KEY_LEN)
            .enumerate()
            .for_each(|(i, chunk)| {
                let shared_secret = e_priv_key
                    .diffie_hellman(&PublicKey::from(pub_keys[i]))
                    .to_bytes();

                let mut key_cipher = {
                    use chacha20::cipher::KeyIvInit;
                    ChaCha::new(&shared_secret.into(), &nonce)
                };

                let mut buffer = content_key.to_vec();
                key_cipher.apply_keystream(&mut buffer);

                chunk[0..KEY_LEN].copy_from_slice(&buffer);
            });

        #[cfg(not(feature = "multi-thread"))]
        encrypted_keys
            .chunks_mut(KEY_LEN)
            .enumerate()
            .for_each(|(i, chunk)| {
                let shared_secret = e_priv_key
                    .diffie_hellman(&PublicKey::from(pub_keys[i]))
                    .to_bytes();

                let mut key_cipher = {
                    use chacha20::cipher::KeyIvInit;
                    ChaCha::new(&shared_secret.into(), &nonce)
                };

                let mut buffer = content_key.to_vec();
                key_cipher.apply_keystream(&mut buffer);

                chunk[0..KEY_LEN].copy_from_slice(&buffer);
            });

        out.extend(encrypted_keys);

        #[cfg(feature = "multi-thread")]
        let encrypted_content = sign_and_encrypt_handle.join().unwrap()?;
        out.extend(encrypted_content);

        Ok(out)
    }

    pub fn extract_content_for_key_position(
        encrypted_content: &mut Vec<u8>,
        position: u16,
    ) -> Result<&[u8], &'static str> {
        let keys_header_start = NONCE_LEN + KEY_LEN;

        let (keys_header_len, keys_count): (usize, usize) = {
            let keys_header_size = encrypted_content[keys_header_start];

            if keys_header_size < 64 {
                (1, keys_header_size as usize)
            } else {
                match (keys_header_size >> 6) & 0b11 {
                    0 => (2, encrypted_content[keys_header_start + 1] as usize + 63),
                    1 => (
                        3,
                        u16::from_be_bytes(
                            encrypted_content[keys_header_start + 1..keys_header_start + 3]
                                .try_into()
                                .unwrap(),
                        ) as usize
                            + 63,
                    ),
                    2 => (
                        5,
                        u32::from_be_bytes(
                            encrypted_content[keys_header_start + 1..keys_header_start + 5]
                                .try_into()
                                .unwrap(),
                        ) as usize
                            + 63,
                    ),
                    3 => (
                        9,
                        u64::from_be_bytes(
                            encrypted_content[keys_header_start + 1..keys_header_start + 9]
                                .try_into()
                                .unwrap(),
                        ) as usize
                            + 63,
                    ),
                    _ => return Err("unknown keys header value"),
                }
            }
        };

        let keys_start = keys_header_start + keys_header_len;
        let encrypted_key_start = keys_start + (position as usize * KEY_LEN);

        let encrypted_content_start = keys_start + (keys_count * KEY_LEN);

        encrypted_content.copy_within(
            encrypted_key_start..encrypted_key_start + KEY_LEN,
            keys_header_start,
        );
        encrypted_content.copy_within(encrypted_content_start.., keys_header_start + KEY_LEN);
        encrypted_content
            .truncate(encrypted_content.len() - keys_header_len - ((keys_count - 1) * KEY_LEN));

        Ok(encrypted_content)
    }

    pub fn decrypt(
        verifying_key: Option<&[u8; 32]>,
        priv_key: [u8; KEY_LEN],
        encrypted_content: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let nonce: [u8; NONCE_LEN] = match encrypted_content[0..NONCE_LEN].try_into() {
            Ok(key) => key,
            Err(_) => return Err("failed to convert nonce to bytes"),
        };

        let ot_pub_key: [u8; KEY_LEN] =
            match encrypted_content[NONCE_LEN..NONCE_LEN + KEY_LEN].try_into() {
                Ok(key) => key,
                Err(_) => return Err("failed to convert pub key to bytes"),
            };

        let mut content_key =
            encrypted_content[NONCE_LEN + KEY_LEN..NONCE_LEN + KEY_LEN + KEY_LEN].to_vec();

        let priv_key = StaticSecret::from(priv_key);
        let shared_secret = priv_key.diffie_hellman(&ot_pub_key.into()).to_bytes();

        let mut key_cipher = {
            use chacha20::cipher::KeyIvInit;
            ChaCha::new(&shared_secret.into(), &nonce.into())
        };

        key_cipher.apply_keystream(&mut content_key);

        let content_key: [u8; KEY_LEN] = match content_key.try_into() {
            Ok(key_bytes) => key_bytes,
            Err(_) => return Err("failed to convert content key to bytes"),
        };

        let content_cipher = {
            use chacha20poly1305::KeyInit;
            ChaChaAEAD::new(&content_key.into())
        };

        match content_cipher.decrypt(
            &nonce.into(),
            &encrypted_content[NONCE_LEN + KEY_LEN + KEY_LEN..],
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
