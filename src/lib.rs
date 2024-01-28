/*
ordinal_crypto is the cryptography library for the Ordinal Platform

Copyright (C) 2024 sean watters

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

use base64::{engine::general_purpose::STANDARD as b64, Engine};

use aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit};
use aes_gcm::aes;
use aes_gcm::aes::cipher::{BlockDecrypt, BlockEncrypt};

use ed25519_dalek::{Signer, Verifier};

/// for converting any string into 32 bytes.
///
/// uses `blake3`.
///
/// ```rust
/// let as_bytes = ordinal_crypto::str_to_32_bytes("make me bytes");
///
/// assert_eq!(as_bytes, [203, 45, 149, 129, 3, 178, 1, 67, 250, 246, 202, 173, 92, 191, 166, 179, 92, 88, 254, 10, 57, 47, 185, 199, 203, 181, 239, 189, 52, 121, 135, 86]);
///```
pub fn str_to_32_bytes(val: &str) -> [u8; 32] {
    let result = blake3::hash(val.as_bytes());
    *result.as_bytes()
}

/// for converting 32 byte keys to/from strings.
///
/// uses `base64::engine::general_purpose::STANDARD`.
///
/// ```rust
/// let key = [0u8; 32];
///
/// let key_str = ordinal_crypto::encode_32_bytes_to_string(&key);
///
/// assert_eq!(key_str, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
///
/// let decoded_key = ordinal_crypto::decode_32_bytes_from_string(&key_str).unwrap();
///
/// assert_eq!(decoded_key, key);
///```
pub fn encode_32_bytes_to_string(val: &[u8; 32]) -> String {
    b64.encode(val)
}

pub fn decode_32_bytes_from_string(val: &str) -> Result<[u8; 32], &'static str> {
    let decoded_val = match b64.decode(val) {
        Ok(val) => val,
        Err(_) => return Err("failed to decode val"),
    };

    let decoded_val_as_bytes: [u8; 32] = match decoded_val.try_into() {
        Ok(val) => val,
        Err(_) => return Err("failed to convert decoded val into fixed bytes"),
    };

    Ok(decoded_val_as_bytes)
}

/// for encrypting one-time content keys.
///
/// uses `aes::Aes256` to encrypt 2, 16 byte, blocks.
///
/// ```rust
/// let key = [0u8; 32];
/// let priv_key = [1u8; 32];
///
/// let encrypted_priv_key = ordinal_crypto::block_encrypt_32_bytes(&key, &priv_key).unwrap();
///
/// assert_eq!(encrypted_priv_key, [123, 195, 2, 108, 215, 55, 16, 62, 98, 144, 43, 205, 24, 251, 1, 99, 123, 195, 2, 108, 215, 55, 16, 62, 98, 144, 43, 205, 24, 251, 1, 99]);
///
/// let decrypted_priv_key = ordinal_crypto::block_decrypt_32_bytes(&key, &encrypted_priv_key).unwrap();
///
/// assert_eq!(priv_key, decrypted_priv_key);
/// ```
pub fn block_encrypt_32_bytes(
    key: &[u8; 32],
    content: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let cipher = aes::Aes256Enc::new(GenericArray::from_slice(key));

    let block_one: [u8; 16] = match content[0..16].try_into() {
        Ok(block) => block,
        Err(_) => return Err("failed to convert block one to fixed bytes"),
    };
    let block_two: [u8; 16] = match content[16..32].try_into() {
        Ok(block) => block,
        Err(_) => return Err("failed to convert block two to fixed bytes"),
    };

    let mut block_one_as_generic_array = GenericArray::from(block_one);
    let mut block_two_as_generic_array = GenericArray::from(block_two);

    cipher.encrypt_block(&mut block_one_as_generic_array);
    cipher.encrypt_block(&mut block_two_as_generic_array);

    let mut combined_array: [u8; 32] = [0u8; 32];

    combined_array[0..16].copy_from_slice(block_one_as_generic_array.as_slice());
    combined_array[16..32].copy_from_slice(block_two_as_generic_array.as_slice());

    Ok(combined_array)
}

pub fn block_decrypt_32_bytes(
    key: &[u8; 32],
    encrypted_content: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let cipher = aes::Aes256Dec::new(GenericArray::from_slice(key));

    let block_one: [u8; 16] = match encrypted_content[0..16].try_into() {
        Ok(block) => block,
        Err(_) => return Err("failed to convert block one to fixed bytes"),
    };
    let block_two: [u8; 16] = match encrypted_content[16..32].try_into() {
        Ok(block) => block,
        Err(_) => return Err("failed to convert block two to fixed bytes"),
    };

    let mut block_one_as_generic_array = GenericArray::from(block_one);
    let mut block_two_as_generic_array = GenericArray::from(block_two);

    cipher.decrypt_block(&mut block_one_as_generic_array);
    cipher.decrypt_block(&mut block_two_as_generic_array);

    let mut combined_array: [u8; 32] = [0; 32];

    combined_array[0..16].copy_from_slice(block_one_as_generic_array.as_slice());
    combined_array[16..32].copy_from_slice(block_two_as_generic_array.as_slice());

    Ok(combined_array)
}

/// for securely encrypting/decrypting remotely stored data.
///
/// AEAD adds 28 bytes (including the 12 byte nonce) to the encrypted result.
///
/// ```rust
/// let key = [0u8; 32];
/// let content = vec![0u8; 1024];
///
/// let encrypted_content = ordinal_crypto::aead_block_encrypt(&key, &content).unwrap();
/// assert_eq!(encrypted_content.len(), content.len() + 28);
///
/// let decrypted_content = ordinal_crypto::aead_block_decrypt(&key, &encrypted_content).unwrap();
/// assert_eq!(decrypted_content, content);
/// ```
pub fn aead_block_encrypt(key: &[u8; 32], content: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = aes_gcm::Aes256Gcm::new(key.into());
    let nonce = aes_gcm::Aes256Gcm::generate_nonce(&mut rand_core::OsRng);

    let ciphertext = match cipher.encrypt(&nonce, content) {
        Ok(ct) => ct,
        Err(_) => return Err("failed to encrypt"),
    };

    let mut out = vec![];

    out.extend(nonce);
    out.extend(ciphertext);

    Ok(out)
}

pub fn aead_block_decrypt(
    key: &[u8; 32],
    encrypted_content: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = aes_gcm::Aes256Gcm::new(key.into());

    let nonce_as_bytes: [u8; 12] = match encrypted_content[0..12].try_into() {
        Ok(v) => v,
        Err(_) => return Err("failed to convert block one to fixed bytes"),
    };

    let nonce = aes_gcm::Nonce::from(nonce_as_bytes);

    match cipher.decrypt(&nonce, &encrypted_content[12..]) {
        Ok(out) => Ok(out),
        Err(_) => Err("failed to decrypt"),
    }
}

/// for signing/verifying content and request payloads.
///
/// uses `ed25519_dalek` to sign the content.
///
/// ```rust
/// let (fingerprint, verifying_key) = ordinal_crypto::generate_fingerprint();
///
/// let content = vec![0u8; 1024];
///
/// let signature = ordinal_crypto::sign_content(&content, &fingerprint);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = ordinal_crypto::verify_signature(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```

pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
    let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    (
        fingerprint.to_bytes(),
        fingerprint.verifying_key().to_bytes(),
    )
}

pub fn sign_content(content: &[u8], fingerprint: &[u8; 32]) -> [u8; 64] {
    let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
    let signature = fingerprint.sign(content);

    signature.to_bytes()
}

pub fn verify_signature(
    signature: &[u8; 64],
    verifying_key: &[u8; 32],
    content: &[u8],
) -> Result<(), &'static str> {
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(verifying_key) {
        Ok(vk) => vk,
        Err(_) => return Err("failed to generate verifying key from pub signing key"),
    };

    match verifying_key.verify(content, &signature) {
        Ok(_) => Ok(()),
        Err(_) => return Err("failed to verify signature for content"),
    }
}

/// for generating pub/priv keys which are used for asymmetrical encryption.
///
/// ```rust
/// let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
///
/// assert_eq!(priv_key.len(), 32);
/// assert_eq!(pub_key.len(), 32);
/// ```
pub fn generate_exchange_keys() -> ([u8; 32], [u8; 32]) {
    let priv_key = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let pub_key = x25519_dalek::PublicKey::from(&priv_key);

    (*priv_key.as_bytes(), *pub_key.as_bytes())
}

/// ties everything together as the core encryption/signing logic.
///
/// ```rust
/// let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
/// let (fingerprint, verifying_key) = ordinal_crypto::generate_fingerprint();
///
/// let content = vec![0u8; 1024];
///
/// let (key_sets, encrypted_content) =
///     ordinal_crypto::encrypt_content(&fingerprint, &content, &pub_key)
///         .unwrap();
///
/// let mut encrypted_content_key = [0u8; 32];
/// encrypted_content_key[0..32].copy_from_slice(&key_sets[32..64]);
///
/// let decrypted_content = ordinal_crypto::decrypt_content(
///     Some(&verifying_key),
///     priv_key,
///
///     &encrypted_content_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub fn encrypt_content(
    fingerprint: &[u8; 32],
    content: &[u8],
    pub_keys: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // sign inner
    let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
    let mut content_signature = fingerprint.sign(content).to_vec();

    content_signature.extend(content);

    // encrypt
    let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let content_key = chacha20poly1305::XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

    let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&content_key);

    let encrypted_content = match content_cipher.encrypt(&nonce, content_signature.as_ref()) {
        Ok(ec) => ec,
        Err(_) => return Err("failed to encrypt content"),
    };

    // per-recipient encryption and addressing

    // 256 bit [u8; 32] pub_key
    // 256 bit [u8; 32] encrypted_content_key
    let mut key_sets: Vec<u8> = vec![];

    let (ot_priv_key, ot_pub_key) = generate_exchange_keys();
    let ot_priv_key = x25519_dalek::StaticSecret::from(ot_priv_key);

    for pub_key in pub_keys.chunks(32) {
        let pub_key_as_bytes: [u8; 32] = match pub_key.try_into() {
            Ok(v) => v,
            Err(_) => return Err("failed to convert pub key to fixed bytes"),
        };

        let shared_secret = ot_priv_key
            .diffie_hellman(&x25519_dalek::PublicKey::from(pub_key_as_bytes))
            .to_bytes();

        let content_key_as_bytes: [u8; 32] = match content_key.try_into() {
            Ok(v) => v,
            Err(_) => return Err("failed to convert content key to fixed bytes"),
        };

        match block_encrypt_32_bytes(&shared_secret, &content_key_as_bytes) {
            Ok(encrypted_content_key) => {
                key_sets.extend(pub_key_as_bytes);
                key_sets.extend(encrypted_content_key);
            }
            Err(err) => return Err(err),
        };
    }

    let mut out = ot_pub_key.to_vec();

    out.extend(nonce);
    out.extend(encrypted_content);

    Ok((key_sets, out))
}

pub fn decrypt_content(
    verifying_key: Option<&[u8; 32]>,
    priv_key: [u8; 32],

    content_key: &[u8; 32],
    encrypted_content: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let pub_key: [u8; 32] = match encrypted_content[0..32].try_into() {
        Ok(key) => key,
        Err(_) => return Err("failed to convert pub key to fixed bytes bytes"),
    };

    let nonce: [u8; 24] = match encrypted_content[32..56].try_into() {
        Ok(key) => key,
        Err(_) => return Err("failed to convert nonce to fixed bytes bytes"),
    };

    let priv_key = x25519_dalek::StaticSecret::from(priv_key);
    let ot_pub_key = x25519_dalek::PublicKey::from(pub_key);

    let shared_secret = priv_key.diffie_hellman(&ot_pub_key).to_bytes();

    let content_key = match block_decrypt_32_bytes(&shared_secret, content_key) {
        Ok(key) => key,
        Err(err) => return Err(err),
    };

    let content_cipher =
        chacha20poly1305::XChaCha20Poly1305::new(GenericArray::from_slice(&content_key));

    match content_cipher.decrypt(
        &chacha20poly1305::XNonce::from(nonce),
        &encrypted_content[56..],
    ) {
        Ok(content) => {
            let signature_as_bytes: [u8; 64] = match content[0..64].try_into() {
                Ok(v) => v,
                Err(_) => return Err("failed to convert signature to fixed bytes"),
            };

            let content = content[64..].to_vec();

            match verifying_key {
                Some(vk) => match verify_signature(&signature_as_bytes, vk, &content) {
                    Ok(_) => Ok(content),
                    Err(_) => Err("failed to verify signature"),
                },
                None => Ok(content),
            }
        }
        Err(_) => return Err("failed to decrypt content"),
    }
}
