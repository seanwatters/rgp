/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::{bytes_to_usize, KEM_CIPHERTEXT_SIZE, KEY_SIZE, NONCE_SIZE};

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
