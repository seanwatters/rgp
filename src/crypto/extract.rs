/*
Copyright (c) 2024 Ordinary Labs

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::{
    dh_extract, hmac_extract, kem_extract, session_extract, DH_MODE, DH_WITH_HMAC_MODE, HMAC_MODE,
    KEM_CIPHERTEXT_SIZE, KEM_MODE, KEM_WITH_DH_HYBRID_MODE, KEY_SIZE, SESSION_MODE,
    SESSION_WITH_KEYGEN_MODE,
};

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
    let mode = encrypted_content[encrypted_content.len() - 1];

    match mode {
        HMAC_MODE => Components::Hmac(hmac_extract(encrypted_content)),
        SESSION_MODE | SESSION_WITH_KEYGEN_MODE => Components::Session(session_extract(
            encrypted_content,
            mode == SESSION_WITH_KEYGEN_MODE,
        )),
        DH_MODE | DH_WITH_HMAC_MODE => Components::Dh(
            dh_extract(position, encrypted_content),
            mode == DH_WITH_HMAC_MODE,
        ),
        KEM_MODE | KEM_WITH_DH_HYBRID_MODE => {
            let (content_key, ciphertext) = kem_extract(position, encrypted_content);
            Components::Kem(content_key, ciphertext, mode == KEM_WITH_DH_HYBRID_MODE)
        }
        _ => unimplemented!(),
    }
}
