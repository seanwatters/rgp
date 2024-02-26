/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::super::{base_decrypt, base_encrypt, usize_to_bytes, KEY_SIZE};

#[cfg(feature = "multi-thread")]
use rayon::prelude::*;
#[cfg(feature = "multi-thread")]
use std::sync::mpsc::channel;

use blake2::digest::{FixedOutput, Mac};
use chacha20::{
    cipher::{generic_array::GenericArray, typenum, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::XChaCha20Poly1305;
use x25519_dalek::StaticSecret;

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

/// per-recipient content key encryption.
#[inline(always)]
fn dh_encrypt_keys(
    priv_key: [u8; KEY_SIZE],
    pub_keys: &Vec<[u8; KEY_SIZE]>,
    hmac_key: Option<[u8; KEY_SIZE]>,
    nonce: &GenericArray<u8, typenum::U24>,
    content_key: &GenericArray<u8, typenum::U32>,
) -> ((usize, [u8; 9]), Vec<u8>) {
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

/// dh encryption.
#[inline(always)]
pub fn dh_encrypt(
    fingerprint: [u8; 32],
    nonce: GenericArray<u8, typenum::U24>,
    out: &mut Vec<u8>,
    mut content: Vec<u8>,
    priv_key: [u8; KEY_SIZE],
    pub_keys: &Vec<[u8; KEY_SIZE]>,
    hmac_key: Option<[u8; KEY_SIZE]>,
) -> Result<[u8; KEY_SIZE], &'static str> {
    use chacha20poly1305::KeyInit;
    let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

    #[cfg(feature = "multi-thread")]
    let (sender, receiver) = channel();

    #[cfg(feature = "multi-thread")]
    rayon::spawn(move || {
        let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content);
        sender.send(encrypted_content).unwrap();
    });

    let ((size, bytes), keys) = dh_encrypt_keys(priv_key, pub_keys, hmac_key, &nonce, &key);
    out.extend_from_slice(&bytes[..size]);
    out.extend(keys);

    #[cfg(feature = "multi-thread")]
    let encrypted_content = receiver.recv().unwrap()?;
    #[cfg(not(feature = "multi-thread"))]
    let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content)?;

    out.extend(encrypted_content);

    Ok(key.into())
}

/// dh decryption.
#[inline(always)]
pub fn dh_decrypt(
    verifier: Option<&[u8; 32]>,
    nonce: &GenericArray<u8, typenum::U24>,
    encrypted_content: &[u8],

    mut encrypted_key: [u8; KEY_SIZE],
    pub_key: [u8; KEY_SIZE],
    priv_key: [u8; KEY_SIZE],
    hmac_key: Option<[u8; KEY_SIZE]>,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
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

    base_decrypt(verifier, nonce, encrypted_key.into(), encrypted_content)
}
