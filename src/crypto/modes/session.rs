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
use chacha20poly1305::{AeadCore, XChaCha20Poly1305};

/// #
/// **ENCRYPTED FORMAT:**
/// - nonce = 24 bytes
/// - encrypted content = content.len()
/// - signature = 64 bytes (encrypted along with the content)
/// - Poly1305 MAC = 16 bytes
/// - mode = 1 byte (set to SESSION_MODE)
///
/// **PROCESS:**
/// 1. Generate one-time components
///     - nonce
/// 2. Sign plaintext to generate content signature
/// 3. Encrypt plaintext and content signature with the content or session key
pub const SESSION_MODE: u8 = 0;

/// #
/// **ENCRYPTED FORMAT:**
/// - nonce = 24 bytes
/// - encrypted key = 32 bytes (`Session` with keygen only)
/// - encrypted content = content.len()
/// - signature = 64 bytes (encrypted along with the content)
/// - Poly1305 MAC = 16 bytes
/// - mode = 1 byte (set to SESSION_WITH_KEYGEN_MODE)
///
/// **PROCESS:**
/// 1. Generate one-time components
///     - nonce
///     - content key
/// 2. Sign plaintext to generate content signature
/// 3. Encrypt plaintext and content signature with the content or session key
/// 4. Encrypt content key with session key
pub const SESSION_WITH_KEYGEN_MODE: u8 = 3;

/// session encryption.
#[inline(always)]
pub fn session_encrypt(
    fingerprint: [u8; 32],
    mut content: Vec<u8>,
    session_key: [u8; KEY_SIZE],
    with_keygen: bool,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    if with_keygen {
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

        out.push(SESSION_WITH_KEYGEN_MODE);

        Ok((out, content_key.into()))
    } else {
        let encrypted_content =
            base_encrypt(fingerprint, &nonce, &session_key.into(), &mut content)?;
        out.extend(encrypted_content);

        out.push(SESSION_MODE);

        Ok((out, session_key))
    }
}

// session decryption.
#[inline(always)]
pub fn session_decrypt(
    verifier: Option<&[u8; 32]>,
    encrypted_content: &[u8],

    session_key: [u8; KEY_SIZE],
    encrypted_key: Option<[u8; KEY_SIZE]>,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = &GenericArray::<u8, typenum::U24>::from_slice(&encrypted_content[0..NONCE_SIZE]);
    let encrypted_content = &encrypted_content[NONCE_SIZE..];

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
    with_keygen: bool,
) -> Option<[u8; KEY_SIZE]> {
    if with_keygen {
        let encrypted_key: [u8; KEY_SIZE] = encrypted_content[NONCE_SIZE..NONCE_SIZE + KEY_SIZE]
            .try_into()
            .unwrap();

        encrypted_content.copy_within(NONCE_SIZE + KEY_SIZE.., NONCE_SIZE);
        encrypted_content.truncate(encrypted_content.len() - KEY_SIZE - 1);

        Some(encrypted_key)
    } else {
        encrypted_content.pop().expect("remove mode byte");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{session_decrypt, session_encrypt, session_extract};

    #[test]
    fn test_session() {
        let (fingerprint, verifier) = crate::generate_fingerprint();
        let (session_key, _) = crate::generate_dh_keys();

        let content = vec![0u8; 1024];

        let (mut encrypted_content, content_key) =
            session_encrypt(fingerprint, content.clone(), session_key, false).unwrap();

        session_extract(&mut encrypted_content, false);

        let (decrypted_content, decrypted_content_key) =
            session_decrypt(Some(&verifier), &encrypted_content, session_key, None).unwrap();

        assert_eq!(content, decrypted_content);
        assert_eq!(content_key, decrypted_content_key);
    }

    #[test]
    fn test_session_with_keygen() {
        let (fingerprint, verifier) = crate::generate_fingerprint();
        let (session_key, _) = crate::generate_dh_keys();

        let content = vec![0u8; 1024];

        let (mut encrypted_content, content_key) =
            session_encrypt(fingerprint, content.clone(), session_key, true).unwrap();

        let encrypted_key = session_extract(&mut encrypted_content, true);

        let (decrypted_content, decrypted_content_key) = session_decrypt(
            Some(&verifier),
            &encrypted_content,
            session_key,
            encrypted_key,
        )
        .unwrap();

        assert_eq!(content, decrypted_content);
        assert_eq!(content_key, decrypted_content_key);
    }
}
