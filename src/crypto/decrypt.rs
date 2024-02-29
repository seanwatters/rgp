/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::{
    dh_decrypt, hmac_decrypt, kem_decrypt, session_decrypt, KEM_CIPHERTEXT_SIZE,
    KEM_SECRET_KEY_SIZE, KEY_SIZE,
};

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
    match mode {
        Decrypt::Session(session_key, encrypted_key) => {
            session_decrypt(verifier, encrypted_content, session_key, encrypted_key)
        }
        Decrypt::Hmac(hmac_key, hmac_value) => {
            hmac_decrypt(verifier, encrypted_content, hmac_key, hmac_value)
        }
        Decrypt::Dh(encrypted_key, pub_key, priv_key, hmac_key) => dh_decrypt(
            verifier,
            encrypted_content,
            encrypted_key,
            pub_key,
            priv_key,
            hmac_key,
        ),
        Decrypt::Kem(encrypted_key, ciphertext, secret_key, dh_components) => kem_decrypt(
            verifier,
            encrypted_content,
            encrypted_key,
            ciphertext,
            secret_key,
            dh_components,
        ),
    }
}
