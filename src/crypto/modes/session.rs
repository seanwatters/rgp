/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::super::{base_decrypt, base_encrypt, KEY_SIZE, NONCE_SIZE};

use chacha20::{
    cipher::{generic_array::GenericArray, typenum, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::XChaCha20Poly1305;

pub const SESSION_MODE: u8 = 0;
pub const SESSION_WITH_KEY_GEN_MODE: u8 = 3;

/// session encryption.
#[inline(always)]
pub fn session_encrypt(
    fingerprint: [u8; 32],
    nonce: GenericArray<u8, typenum::U24>,
    out: &mut Vec<u8>,
    mut content: Vec<u8>,
    with_key_gen: bool,
    session_key: [u8; KEY_SIZE],
) -> Result<[u8; KEY_SIZE], &'static str> {
    if with_key_gen {
        let content_key = {
            use chacha20poly1305::KeyInit;
            XChaCha20Poly1305::generate_key(&mut rand_core::OsRng)
        };

        let mut key_cipher = {
            use chacha20::cipher::KeyIvInit;
            XChaCha20::new(&session_key.into(), &nonce)
        };

        let encrypted_content = base_encrypt(fingerprint, &nonce, &content_key, &mut content)?;

        let mut encrypted_key = content_key.clone();
        key_cipher.apply_keystream(&mut encrypted_key);

        out.extend(encrypted_key);
        out.extend(encrypted_content);

        Ok(content_key.into())
    } else {
        let encrypted_content =
            base_encrypt(fingerprint, &nonce, &session_key.into(), &mut content)?;
        out.extend(encrypted_content);

        Ok(session_key)
    }
}

// session decryption.
#[inline(always)]
pub fn session_decrypt(
    verifier: Option<&[u8; 32]>,
    nonce: &GenericArray<u8, typenum::U24>,
    encrypted_content: &[u8],

    session_key: [u8; KEY_SIZE],
    encrypted_key: Option<[u8; KEY_SIZE]>,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    if let Some(mut encrypted_key) = encrypted_key {
        let mut key_cipher = {
            use chacha20::cipher::KeyIvInit;
            XChaCha20::new(&session_key.into(), nonce)
        };

        key_cipher.apply_keystream(&mut encrypted_key);

        base_decrypt(verifier, nonce, encrypted_key.into(), encrypted_content)
    } else {
        base_decrypt(verifier, nonce, session_key.into(), encrypted_content)
    }
}

/// extract session components.
#[inline(always)]
pub fn session_extract(
    encrypted_content: &mut Vec<u8>,
    with_key_gen: bool,
) -> Option<[u8; KEY_SIZE]> {
    if with_key_gen {
        let encrypted_key: [u8; KEY_SIZE] = encrypted_content[NONCE_SIZE..NONCE_SIZE + KEY_SIZE]
            .try_into()
            .unwrap();

        encrypted_content.copy_within(NONCE_SIZE + KEY_SIZE.., NONCE_SIZE);
        encrypted_content.truncate(encrypted_content.len() - KEY_SIZE);

        Some(encrypted_key)
    } else {
        None
    }
}
