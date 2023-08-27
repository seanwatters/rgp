/*
ordinal_crypto is the cryptography library for the Ordinal Protocol

Copyright (C) 2023  sean watters

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

use aes::cipher::{BlockDecrypt, BlockEncrypt};
use sha2::Digest;

use chacha20poly1305::aead::{
    generic_array::GenericArray, Aead, AeadCore, KeyInit as ChaChaKeyInit,
};
use ed25519_dalek::{Signer, Verifier};

/// for converting any string into 32 bytes.
///
/// uses `sha2::Sha256`.
///
/// ```rust
/// let as_bytes = ordinal_crypto::string_to_32_bytes("make me bytes".to_string());
///
/// assert_eq!(as_bytes, [243, 18, 105, 68, 75, 11, 125, 15, 101, 58, 188, 97, 128, 7, 71, 10, 116, 148, 220, 199, 229, 138, 77, 148, 243, 21, 1, 110, 128, 6, 204, 115]);
///```
pub fn string_to_32_bytes(val: String) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(val);

    let result = hasher.finalize();
    let out: [u8; 32] = result
        .try_into()
        .expect("failed to convert hashed value to fixed bytes");

    out
}

/// for converting 32 byte `x25519` public keys to strings for indexing.
///
/// uses `base64::encode`.
///
/// ```rust
/// let key = [0u8; 32];
/// let key_str = ordinal_crypto::encode_key_to_string(key);
///
/// assert_eq!(key_str, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
///```
pub fn encode_key_to_string(val: [u8; 32]) -> String {
    #[allow(deprecated)]
    base64::encode(val)
}

/// for hashing usernames stored in the local database for public key routing.
///
/// first turns the username into a 32 byte array with `ordinal_crypto::string_to_32_bytes`,
/// next `ordinal_client::block_encrypt_key` with the provided key, finally `base64::encode`.
///
///```rust
/// let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
///
/// let str_hash = ordinal_crypto::encode_key_to_string_encrypted(pub_key, "username".to_string());
///
/// let as_bytes = ordinal_crypto::string_to_32_bytes("username".to_string());
/// let str_enc = ordinal_crypto::encode_key_to_string(as_bytes);
///
/// assert_ne!(str_hash, str_enc);
///```
pub fn encode_key_to_string_encrypted(key: [u8; 32], val: String) -> String {
    #[allow(deprecated)]
    base64::encode(block_encrypt_key(key, string_to_32_bytes(val)))
}

/// for decoding `x25519` public keys from strings
///
/// uses `base64::decode` and then converts to fixed `[u8; 32]`.
///
/// ```rust
/// let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
/// let pub_key_as_string = ordinal_crypto::encode_key_to_string(pub_key);
///
/// let decoded_key = ordinal_crypto::decode_key_from_string(pub_key_as_string);
///
/// assert_eq!(decoded_key, pub_key);
///```
pub fn decode_key_from_string(val: String) -> [u8; 32] {
    #[allow(deprecated)]
    let decoded_val = base64::decode(val).expect("failed to decode val");

    let decoded_val_as_bytes: &[u8] = &decoded_val;
    let decoded_val_as_fixed_bytes: [u8; 32] = decoded_val_as_bytes
        .try_into()
        .expect("failed to convert decoded val into fixed bytes");

    decoded_val_as_fixed_bytes
}

/// for encrypting most private keys within our protocol.
///
/// uses `aes::Aes256` to encrypt 2, 16 byte, blocks.
///
/// ```rust
/// let encryption_key = [0u8; 32];
/// let (priv_key, _) = ordinal_crypto::generate_exchange_keys();
///
/// let encrypted_priv_key = ordinal_crypto::block_encrypt_key(encryption_key, priv_key);
///
/// assert_ne!(priv_key, encrypted_priv_key);
///
/// let decrypted_priv_key = ordinal_crypto::block_decrypt_key(encryption_key, encrypted_priv_key);
///
/// assert_eq!(priv_key, decrypted_priv_key);
/// ```
pub fn block_encrypt_key(key: [u8; 32], content: [u8; 32]) -> [u8; 32] {
    let cipher = aes::Aes256::new(GenericArray::from_slice(&key));

    let block_one: [u8; 16] = content[0..16]
        .try_into()
        .expect("failed to convert block one to fixed bytes");
    let block_two: [u8; 16] = content[16..32]
        .try_into()
        .expect("failed to convert block two to fixed bytes");

    let mut block_one_as_generic_array = GenericArray::from(block_one);
    let mut block_two_as_generic_array = GenericArray::from(block_two);

    cipher.encrypt_block(&mut block_one_as_generic_array);
    cipher.encrypt_block(&mut block_two_as_generic_array);

    let mut combined_array: [u8; 32] = [0u8; 32];

    combined_array[0..16].copy_from_slice(block_one_as_generic_array.as_slice());
    combined_array[16..32].copy_from_slice(block_two_as_generic_array.as_slice());

    combined_array
}

/// for decrypting keys encrypted with `ordinal_client::block_encrypt_key`.
///
/// uses `aes::Aes256` to decrypt 2, 16 byte, blocks.
///
/// ```rust
/// let encryption_key = [0u8; 32];
/// let (priv_key, _) = ordinal_crypto::generate_exchange_keys();
///
/// let encrypted_priv_key = ordinal_crypto::block_encrypt_key(encryption_key, priv_key);
///
/// assert_ne!(priv_key, encrypted_priv_key);
///
/// let decrypted_priv_key = ordinal_crypto::block_decrypt_key(encryption_key, encrypted_priv_key);
///
/// assert_eq!(priv_key, decrypted_priv_key);
/// ```
pub fn block_decrypt_key(key: [u8; 32], encrypted_content: [u8; 32]) -> [u8; 32] {
    let cipher = aes::Aes256::new(GenericArray::from_slice(&key));

    let block_one: [u8; 16] = encrypted_content[0..16]
        .try_into()
        .expect("failed to convert block one to fixed bytes");
    let block_two: [u8; 16] = encrypted_content[16..32]
        .try_into()
        .expect("failed to convert block two to fixed bytes");

    let mut block_one_as_generic_array = GenericArray::from(block_one);
    let mut block_two_as_generic_array = GenericArray::from(block_two);

    cipher.decrypt_block(&mut block_one_as_generic_array);
    cipher.decrypt_block(&mut block_two_as_generic_array);

    let mut combined_array: [u8; 32] = [0; 32];

    combined_array[0..16].copy_from_slice(block_one_as_generic_array.as_slice());
    combined_array[16..32].copy_from_slice(block_two_as_generic_array.as_slice());

    combined_array
}

/// for encrypting signatures.
///
/// uses `ordinal_crypto::block_encrypt_key` to encrypt 2, 32 byte, blocks.
///
/// ```rust
/// let encryption_key = [0u8; 32];
/// let signature = [0u8; 64];
///
/// let encrypted_sig = ordinal_crypto::block_encrypt_signature(encryption_key, signature);
///
/// assert_ne!(signature, encrypted_sig);
///
/// let decrypted_sig = ordinal_crypto::block_decrypt_signature(encryption_key, encrypted_sig);
///
/// assert_eq!(signature, decrypted_sig);
/// ```
pub fn block_encrypt_signature(key: [u8; 32], content: [u8; 64]) -> [u8; 64] {
    let block_one: [u8; 32] = content[0..32]
        .try_into()
        .expect("failed to convert block one to fixed bytes");
    let block_two: [u8; 32] = content[32..64]
        .try_into()
        .expect("failed to convert block two to fixed bytes");

    let block_one_encrypted = block_encrypt_key(key, block_one);
    let block_two_encrypted = block_encrypt_key(key, block_two);

    let mut combined_array: [u8; 64] = [0; 64];

    combined_array[0..32].copy_from_slice(block_one_encrypted.as_slice());
    combined_array[32..64].copy_from_slice(block_two_encrypted.as_slice());

    combined_array
}

/// for decrypting signatures.
///
/// uses `ordinal_crypto::block_decrypt_key` to decrypt 2, 32 byte, blocks.
///
/// ```rust
/// let encryption_key = [0u8; 32];
/// let signature = [0u8; 64];
///
/// let encrypted_sig = ordinal_crypto::block_encrypt_signature(encryption_key, signature);
///
/// assert_ne!(signature, encrypted_sig);
///
/// let decrypted_sig = ordinal_crypto::block_decrypt_signature(encryption_key, encrypted_sig);
///
/// assert_eq!(signature, decrypted_sig);
pub fn block_decrypt_signature(key: [u8; 32], encrypted_content: [u8; 64]) -> [u8; 64] {
    let block_one: [u8; 32] = encrypted_content[0..32]
        .try_into()
        .expect("failed to convert block one to fixed bytes");
    let block_two: [u8; 32] = encrypted_content[32..64]
        .try_into()
        .expect("failed to convert block two to fixed bytes");

    let block_one_decrypted = block_decrypt_key(key, block_one);
    let block_two_decrypted = block_decrypt_key(key, block_two);

    let mut combined_array: [u8; 64] = [0; 64];

    combined_array[0..32].copy_from_slice(block_one_decrypted.as_slice());
    combined_array[32..64].copy_from_slice(block_two_decrypted.as_slice());

    combined_array
}

/// for generating a user's initial signing keys.
///
/// uses `ed25519_dalek` to generate the keys.
///
/// ```rust
/// let (signing_key, verifying_key) = ordinal_crypto::generate_signing_keys();
///
/// assert_eq!(signing_key.len(), 32);
/// assert_eq!(verifying_key.len(), 32);
/// ```
pub fn generate_signing_keys() -> ([u8; 32], [u8; 32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    (
        signing_key.to_bytes(),
        signing_key.verifying_key().to_bytes(),
    )
}

/// for signing "inner" content and encrypted request payloads.
///
/// uses `ed25519_dalek` to sign the content.
///
/// ```rust
/// let (signing_key, verifying_key) = ordinal_crypto::generate_signing_keys();
///
/// let content = vec![0u8; 1024];
/// let signature = ordinal_crypto::sign_content(content.clone(), signing_key);
///
/// assert_eq!(signature.len(), 64);
/// ```
pub fn sign_content(content: Vec<u8>, signing_key: [u8; 32]) -> [u8; 64] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key);
    let signature = signing_key.sign(&content);

    signature.to_bytes()
}

/// for verifying signatures on "inner" content and request encrypted payloads.
///
/// uses `ed25519_dalek` to sign the content.
///
/// ```rust
/// let (signing_key, verifying_key) = ordinal_crypto::generate_signing_keys();
///
/// let content = vec![0u8; 1024];
/// let signature = ordinal_crypto::sign_content(content.clone(), signing_key);
/// let signature_verified = ordinal_crypto::verify_signature(signature, verifying_key, content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
pub fn verify_signature(
    signature: [u8; 64],
    verifying_key: [u8; 32],
    content: Vec<u8>,
) -> Result<(), String> {
    let signature = ed25519_dalek::Signature::from_bytes(&signature);
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&verifying_key) {
        Ok(vk) => vk,
        Err(err) => {
            return Err(format!(
                "failed to generate verifying key from pub signing key: {}",
                err.to_string()
            ))
        }
    };

    match verifying_key.verify(&content, &signature) {
        Ok(_) => Ok(()),
        Err(err) => {
            return Err(format!(
                "failed to verify signature for content: {}",
                err.to_string()
            ))
        }
    }
}

/// for generating exchange keys which are used for the whole e2ee part.
///
/// uses `x25519_dalek` to generate a `StaticSecret`. while the use of
/// static secrets is discouraged, they're only used and valid for a window
/// of time. for each message that is sent, a brand new `ChaCha20` private
/// key and nonce are created, thus guaranteeing forward secrecy in that
/// dimension. as it pertains to forward secrecy for the `x25519` encryption,
/// we essentially have "batched" forward secrecy on the recipients' side,
/// for the set of messages that are encrypted with a given private key's public
/// key for that period of time, but on the sender's side a brand new `x25519` private
/// key is also generated and thrown away for each message. the `StaticSecret` which is
/// stored, is only ever stored, encrypted with `AES256` and is not designed to leave a user's device
/// (barring something like a "key export" if we wanted to make taking copies
/// of your on-device data with you easier).
///
/// ```rust
/// let (priv_exchange_key, pub_exchange_key) = ordinal_crypto::generate_exchange_keys();
///
/// assert_eq!(priv_exchange_key.len(), 32);
/// assert_eq!(pub_exchange_key.len(), 32);
/// ```
pub fn generate_exchange_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

/// this is the "everything" of the content encryption on the Ordinal Protocol.
///
/// first the content is signed in its unaltered format, and the signature bytes
/// are prefixed to the content prior to encryption, next the content is encrypted
/// using the `XChaCha20Poly1305` cipher with a newly created nonce and private key,
/// next that `ChaCha20` private key is encrypted using a `x25519_dalek::SharedSecret`
/// with a fresh `StaticSecret` that is used only to encrypt this message and _all_
/// of the recipients' public keys (thus adding 64 bytes to the payload for each
/// recipient). the reason we see 64 bytes instead of just 32 (the size of the encrypted
/// `ChaCha20` private key) is that we also need a way for a user to find their personal,
/// encrypted copy of the private `ChaCha20` key, so we pair up the recipients' 32 byte
/// public exchange keys with their copy, inside a giant byte array. given that this byte
/// array might get rather large, it may make sense to switch this to a more "map-like" format
/// but we will likely see larger messages being stored in the database. Finally the encrypted
/// content itself is signed (this is for the Ordinal Server to verify the authenticity of the
/// request) and the resulting values are returned.
///
/// ```rust
/// let (priv_exchange_key, pub_exchange_key) = ordinal_crypto::generate_exchange_keys();
/// let (signing_key, _) = ordinal_crypto::generate_signing_keys();
///
/// let content = vec![0u8; 1024];
///
/// let (nonce, key_sets, encrypted_content, sender_public_key) =
///     ordinal_crypto::encrypt_and_sign_content(signing_key, content.clone(), pub_exchange_key.to_vec())
///         .unwrap();
///
/// let mut encrypted_content_key: [u8; 32] = [0u8; 32];
/// encrypted_content_key[0..32].copy_from_slice(&key_sets[32..64]);
///
/// let (decrypted_content, _) = ordinal_crypto::decrypt_content(
///     sender_public_key,
///     priv_exchange_key,
///     encrypted_content_key,
///     nonce,
///     encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
///
/// returns (nonce, key_sets packed together all as one line, encrypted_content, sender_public_key)
pub fn encrypt_and_sign_content(
    signing_key: [u8; 32],
    content: Vec<u8>,
    receiver_pub_exchange_keys: Vec<u8>,
) -> Result<([u8; 24], Vec<u8>, Vec<u8>, [u8; 32]), String> {
    // sign inner
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key);

    let mut content_signature = signing_key.clone().sign(&content).to_vec();
    let verifying_key = signing_key.verifying_key();

    content_signature.extend(verifying_key.as_bytes().to_vec());
    content_signature.extend(content);

    // encrypt
    let private_content_key =
        chacha20poly1305::XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);
    let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&private_content_key);
    let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);

    let encrypted_content = match content_cipher.encrypt(&nonce, content_signature.as_ref()) {
        Ok(ec) => ec,
        Err(err) => return Err(format!("failed to encrypt content: {}", err.to_string())),
    };

    // per-recipient encryption and addressing

    // 256 bit [u8; 32] receiver_pub_exchange_key
    // 256 bit [u8; 32] encrypted_content_key
    let mut key_sets: Vec<u8> = vec![];

    let (sender_priv_key, sender_public_key) = generate_exchange_keys();

    for receiver_pub_exchange_key in receiver_pub_exchange_keys.chunks(32) {
        let sender_priv_exchange_key = x25519_dalek::StaticSecret::from(sender_priv_key);

        let receiver_pub_exchange_key_as_fixed_bytes: [u8; 32] = receiver_pub_exchange_key
            .try_into()
            .expect("failed to convert receiver pub exchange key to fixed bytes");

        let shared_secret = sender_priv_exchange_key
            .diffie_hellman(&x25519_dalek::PublicKey::from(
                receiver_pub_exchange_key_as_fixed_bytes,
            ))
            .to_bytes();

        let encrypted_content_key_as_bytes = private_content_key.as_slice();
        let encrypted_content_key_as_fixed_bytes: [u8; 32] = encrypted_content_key_as_bytes
            .try_into()
            .expect("failed to convert encrypted content key to fixed bytes");

        let encrypted_content_key =
            block_encrypt_key(shared_secret, encrypted_content_key_as_fixed_bytes);

        key_sets.extend(receiver_pub_exchange_key.iter());
        key_sets.extend(encrypted_content_key);
    }

    Ok((nonce.into(), key_sets, encrypted_content, sender_public_key))
}

/// this is the "everything" of the content decryption on the Ordinal Protocol.
///
/// as the receiver, we have a database full of our `x25519_dalek::StaticSecret`s (all encrypted
/// using `AES256`), which are all addressed by their corresponding "stringified" public keys.
/// so, at the time of message receipt, they will retrieve the private key for the public key
/// that the sender encrypted the message with, _with_ that public key.
///
/// first we generate the shared secret with our "windowed" or "batch" `StaticSecret` and the sender's
/// public key, next we decrypt the "content key" (private `ChaCha20` key that was encrypted with this
/// same shared secret, this is just our copy), and finally with the private `ChaCha20` key decrypted
/// we can now decrypt the actual content.  
///
/// ```rust
/// let (priv_exchange_key, pub_exchange_key) = ordinal_crypto::generate_exchange_keys();
/// let (signing_key, _) = ordinal_crypto::generate_signing_keys();
///
/// let content = vec![0u8; 1024];
///
/// let (nonce, key_sets, encrypted_content, sender_public_key) =
///     ordinal_crypto::encrypt_and_sign_content(signing_key, content.clone(), pub_exchange_key.to_vec())
///         .unwrap();
///
/// let mut encrypted_content_key: [u8; 32] = [0u8; 32];
/// encrypted_content_key[0..32].copy_from_slice(&key_sets[32..64]);
///
/// let (decrypted_content, _) = ordinal_crypto::decrypt_content(
///     sender_public_key,
///     priv_exchange_key,
///     encrypted_content_key,
///     nonce,
///     encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
///
/// (content, verifying_key) -> verifying key is to compare against deserialized content
pub fn decrypt_content(
    sender_pub_exchange_key: [u8; 32],
    receiver_priv_exchange_key: [u8; 32],

    encrypted_content_key: [u8; 32],

    nonce: [u8; 24],
    encrypted_content: Vec<u8>,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let sender_pub_exchange_key = x25519_dalek::PublicKey::from(sender_pub_exchange_key);
    let receiver_priv_exchange_key = x25519_dalek::StaticSecret::from(receiver_priv_exchange_key);

    let shared_secret = receiver_priv_exchange_key
        .diffie_hellman(&sender_pub_exchange_key)
        .to_bytes();

    let decrypted_content_key = block_decrypt_key(shared_secret, encrypted_content_key);

    let content_cipher =
        chacha20poly1305::XChaCha20Poly1305::new(GenericArray::from_slice(&decrypted_content_key));

    match content_cipher.decrypt(
        &chacha20poly1305::XNonce::from(nonce),
        encrypted_content.as_ref(),
    ) {
        Ok(content) => {
            let signature_as_bytes = &content[0..64];
            let signature_as_fixed_bytes: [u8; 64] = signature_as_bytes
                .try_into()
                .expect("failed to convert signature to fixed bytes");

            let verifying_key_as_bytes = &content[64..96];
            let verifying_key = verifying_key_as_bytes
                .try_into()
                .expect("failed to convert verifying key to fixed bytes");

            let content = content[96..].to_vec();

            match verify_signature(signature_as_fixed_bytes, verifying_key, content.clone()) {
                Ok(_) => Ok((content, verifying_key)),
                Err(err) => Err(format!("failed to verify signature: {}", err.to_string())),
            }
        }
        Err(err) => return Err(format!("failed to decrypt content: {}", err.to_string())),
    }
}
