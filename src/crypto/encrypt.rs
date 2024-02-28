/*
Copyright (c) 2024 Ordinary Labs

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use std::{fs::File, io::Read};

use super::{dh_encrypt, hmac_encrypt, kem_encrypt, session_encrypt, KemKeyReader, KEY_SIZE};

/// encapsulates the parameters and mode for encryption.
pub enum Encrypt<'a, R: Read = File> {
    /// generates random content key and encrypts for all
    /// recipients with their respective Diffie-Hellman shared secret.
    Dh(
        /// sender private key
        [u8; KEY_SIZE],
        /// recipient public keys
        &'a Vec<[u8; KEY_SIZE]>,
        /// optional HMAC key
        Option<[u8; KEY_SIZE]>,
    ),

    /// hashes the second tuple member, with the first
    /// tuple member as the HMAC key.
    Hmac(
        /// HMAC key
        [u8; KEY_SIZE],
        /// HMAC value
        [u8; KEY_SIZE],
        /// iteration
        usize,
    ),

    /// uses the key that is passed in without modification.
    Session(
        /// session key
        [u8; KEY_SIZE],
        /// with key gen
        bool,
    ),

    /// uses key encapsulation to encrypt a copy of the
    /// a one-time generated content key for each recipient.
    Kem(
        /// recipient KEM public keys reader
        KemKeyReader<R>,
    ),
}

/// signs and encrypts content.
///
/// ```rust
/// # use rgp::{decrypt, extract_components_mut, Components, Decrypt, KemKeyReader, generate_dh_keys, generate_fingerprint, generate_kem_keys};
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
///     // pass Some([u8; 32]) to HMAC the shared secret with the provided key
///     Encrypt::Dh(sender_priv_key, &recipient_pub_keys, None)
/// ).unwrap();
/// # if let Components::Dh(encrypted_key, _) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Dh(encrypted_key, sender_pub_key, receiver_priv_key, None),
/// #     ).unwrap();
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
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
///
/// // Session
/// # let content = content_clone.clone();
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     // specify true/false for keygen mode
///     Encrypt::Session(session_key, false)
/// ).unwrap();
/// # if let Components::Session(encrypted_key) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Session(session_key, encrypted_key),
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
///
/// // KEM
/// # use std::fs::{remove_file, File, OpenOptions};
/// # use std::io::Write;
/// # let content = content_clone.clone();
/// # let (recipient_secret_key, recipient_pub_key) = generate_kem_keys();
/// # let mut pub_keys_file = OpenOptions::new().create(true).write(true).append(true).open("doc_test_kem_pub_keys").unwrap();
/// # pub_keys_file.write_all(&recipient_pub_key).unwrap();
/// # pub_keys_file.flush().unwrap();
/// # let key_reader = KemKeyReader::new(File::open("doc_test_kem_pub_keys").unwrap());
/// let (mut encrypted_content, content_key) = encrypt(
///     fingerprint,
///     content,
///     Encrypt::Kem(key_reader)
/// ).unwrap();
/// # if let Components::Kem(encrypted_key, ciphertext, _) = extract_components_mut(0, &mut encrypted_content) {
/// #     let (decrypted_content, _) = decrypt(
/// #         Some(&verifier),
/// #         &encrypted_content,
/// #         Decrypt::Kem(encrypted_key, ciphertext, recipient_secret_key, None),
/// #     ).unwrap();
/// #
/// #     assert_eq!(decrypted_content, content_clone);
/// # };
/// # remove_file("doc_test_kem_pub_keys").unwrap();
/// ```
pub fn encrypt(
    fingerprint: [u8; 32],
    content: Vec<u8>,
    mode: Encrypt,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    match mode {
        Encrypt::Session(session_key, with_keygen) => {
            session_encrypt(fingerprint, content, session_key, with_keygen)
        }
        Encrypt::Hmac(hmac_key, hmac_value, iteration) => {
            hmac_encrypt(fingerprint, content, hmac_key, hmac_value, iteration)
        }
        Encrypt::Dh(priv_key, pub_keys, hmac_key) => {
            dh_encrypt(fingerprint, content, priv_key, pub_keys, hmac_key)
        }
        Encrypt::Kem(mut key_reader) => kem_encrypt(fingerprint, content, &mut key_reader),
    }
}
