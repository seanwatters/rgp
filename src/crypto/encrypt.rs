/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use chacha20poly1305::{AeadCore, XChaCha20Poly1305};
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
/// # use rgp::{decrypt, extract_components_mut, Components, Decrypt, generate_dh_keys, generate_fingerprint};
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
/// ```
pub fn encrypt(
    fingerprint: [u8; 32],
    content: Vec<u8>,
    mode: Encrypt,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    match mode {
        Encrypt::Session(session_key, with_key_gen) => {
            let key = session_encrypt(
                fingerprint,
                nonce,
                &mut out,
                content,
                with_key_gen,
                session_key,
            )?;

            if with_key_gen {
                out.push(3);
            } else {
                out.push(0);
            }

            Ok((out, key))
        }
        Encrypt::Hmac(hmac_key, hmac_value, iteration) => {
            let key = hmac_encrypt(
                fingerprint,
                nonce,
                &mut out,
                content,
                hmac_key,
                hmac_value,
                iteration,
            )?;

            out.push(1);

            Ok((out, key))
        }
        Encrypt::Dh(priv_key, pub_keys, hmac_key) => {
            let key = dh_encrypt(
                fingerprint,
                nonce,
                &mut out,
                content,
                priv_key,
                pub_keys,
                hmac_key,
            )?;

            if hmac_key.is_some() {
                out.push(4)
            } else {
                out.push(2)
            }

            Ok((out, key))
        }
        Encrypt::Kem(mut key_reader) => {
            let key = kem_encrypt(fingerprint, nonce, &mut out, content, &mut key_reader)?;

            if key_reader.dh_priv_key.is_some() {
                out.push(6);
            } else {
                out.push(5);
            }

            Ok((out, key))
        }
    }
}
