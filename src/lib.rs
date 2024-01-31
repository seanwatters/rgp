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

const NONCE_SIZE: usize = 24;
const ENCRYPTED_KEY_LENGTH: usize = 32;

/// for converting any string into 32 bytes.
///
/// ```rust
/// let as_bytes = ordinal_crypto::hash_str("make me bytes");
///
/// assert_eq!(as_bytes, [140, 80, 144, 129, 175, 43, 30, 228, 156, 242, 68, 212, 88, 54, 57, 61, 153, 171, 132, 241, 152, 87, 192, 17, 182, 131, 148, 93, 31, 156, 227, 133]);
///```
pub fn hash_str(val: &str) -> [u8; 32] {
    use blake2::Digest;

    let mut hasher = blake2::Blake2s256::new();
    hasher.update(val.as_bytes());
    let res = hasher.finalize();

    let mut out = [0u8; 32];
    out[0..32].copy_from_slice(&res);

    out
}

/// for securely encrypting/decrypting remotely stored data.
///
/// ```rust
/// let key = [0u8; 32];
/// let content = vec![0u8; 1024];
///
/// let encrypted_content = ordinal_crypto::aead::encrypt(&key, &content).unwrap();
/// assert_eq!(encrypted_content.len(), content.len() + 40);
///
/// let decrypted_content = ordinal_crypto::aead::decrypt(&key, &encrypted_content).unwrap();
/// assert_eq!(decrypted_content, content);
/// ```
pub mod aead {
    use super::NONCE_SIZE;
    use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};

    pub fn encrypt(key: &[u8; 32], content: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);

        let ciphertext = match cipher.encrypt(&nonce, content) {
            Ok(ct) => ct,
            Err(_) => return Err("failed to encrypt"),
        };

        let mut out = vec![];

        out.extend(nonce);
        out.extend(ciphertext);

        Ok(out)
    }

    pub fn decrypt(key: &[u8; 32], encrypted_content: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(key.into());

        let nonce_as_bytes: [u8; NONCE_SIZE] = match encrypted_content[0..NONCE_SIZE].try_into() {
            Ok(v) => v,
            Err(_) => return Err("failed to convert block one to fixed bytes"),
        };

        match cipher.decrypt(&nonce_as_bytes.into(), &encrypted_content[NONCE_SIZE..]) {
            Ok(out) => Ok(out),
            Err(_) => Err("failed to decrypt"),
        }
    }
}

/// for signing/verifying content and request payloads.
///
/// ```rust
/// let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1024];
///
/// let signature = ordinal_crypto::signature::sign(&fingerprint, &content);
///
/// assert_eq!(signature.len(), 64);
///
/// let signature_verified = ordinal_crypto::signature::verify(&signature, &verifying_key, &content).is_ok();
///
/// assert_eq!(signature_verified, true);
/// ```
pub mod signature {
    use ed25519_dalek::{Signer, Verifier};

    pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
        let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        (
            fingerprint.to_bytes(),
            fingerprint.verifying_key().to_bytes(),
        )
    }

    pub fn sign(fingerprint: &[u8; 32], content: &[u8]) -> [u8; 64] {
        let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
        let signature = fingerprint.sign(content);

        signature.to_bytes()
    }

    pub fn verify(
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
}
pub mod bytes_32 {
    use aes::cipher::{
        generic_array::{typenum, GenericArray},
        BlockDecrypt, BlockEncrypt, KeyInit,
    };
    use base64::{engine::general_purpose::STANDARD as b64, Engine};

    /// for converting 32 byte keys to/from strings.
    ///
    /// ```rust
    /// let key = [0u8; 32];
    ///
    /// let key_str = ordinal_crypto::bytes_32::encode(&key);
    ///
    /// assert_eq!(key_str, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    ///
    /// let decoded_key = ordinal_crypto::bytes_32::decode(&key_str).unwrap();
    ///
    /// assert_eq!(decoded_key, key);
    ///```
    pub fn encode(val: &[u8; 32]) -> String {
        b64.encode(val)
    }

    pub fn decode(val: &str) -> Result<[u8; 32], &'static str> {
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
    /// ```rust
    /// let key = [0u8; 32];
    /// let priv_key = [1u8; 32];
    ///
    /// let encrypted_priv_key = ordinal_crypto::bytes_32::encrypt(&key, &priv_key);
    ///
    /// assert_eq!(encrypted_priv_key, [123, 195, 2, 108, 215, 55, 16, 62, 98, 144, 43, 205, 24, 251, 1, 99, 123, 195, 2, 108, 215, 55, 16, 62, 98, 144, 43, 205, 24, 251, 1, 99]);
    ///
    /// let decrypted_priv_key = ordinal_crypto::bytes_32::decrypt(&key, &encrypted_priv_key);
    ///
    /// assert_eq!(priv_key, decrypted_priv_key);
    /// ```
    pub fn encrypt(key: &[u8; 32], content: &[u8; 32]) -> [u8; 32] {
        let cipher = aes::Aes256Enc::new(key.into());

        let mut block_one = *GenericArray::<u8, typenum::U16>::from_slice(&content[0..16]);
        let mut block_two = *GenericArray::<u8, typenum::U16>::from_slice(&content[16..32]);

        cipher.encrypt_block(&mut block_one);
        cipher.encrypt_block(&mut block_two);

        let mut combined_array: [u8; 32] = [0u8; 32];

        combined_array[0..16].copy_from_slice(&block_one);
        combined_array[16..32].copy_from_slice(&block_two);

        combined_array
    }

    pub fn decrypt(key: &[u8; 32], encrypted_content: &[u8; 32]) -> [u8; 32] {
        let cipher = aes::Aes256Dec::new(key.into());

        let mut block_one =
            *GenericArray::<u8, typenum::U16>::from_slice(&encrypted_content[0..16]);
        let mut block_two =
            *GenericArray::<u8, typenum::U16>::from_slice(&encrypted_content[16..32]);

        cipher.decrypt_block(&mut block_one);
        cipher.decrypt_block(&mut block_two);

        let mut combined_array: [u8; 32] = [0; 32];

        combined_array[0..16].copy_from_slice(&block_one);
        combined_array[16..32].copy_from_slice(&block_two);

        combined_array
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
/// max public key count is 65,535 (~2mb).
///
/// ```rust
/// let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
/// let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
///
/// let content = vec![0u8; 1024];
///
/// let encrypted_content =
///     ordinal_crypto::content::encrypt(&fingerprint, &content, &pub_key).unwrap();
///
/// let (encrypted_content, encrypted_key) =
///     ordinal_crypto::content::extract_components_for_key_position(&encrypted_content, 0).unwrap();
///
/// let decrypted_content = ordinal_crypto::content::decrypt(
///     Some(&verifying_key),
///     priv_key,
///
///     &encrypted_key,
///     &encrypted_content,
/// )
/// .unwrap();
///
/// assert_eq!(decrypted_content, content);
/// ```
pub mod content {
    use super::{ENCRYPTED_KEY_LENGTH, NONCE_SIZE};
    use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};

    pub fn encrypt(
        fingerprint: &[u8; 32],
        content: &[u8],
        pub_keys: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // 65,535 * 32 -> 2_097_120
        if pub_keys.len() > 2_097_120 {
            return Err("cannot encrypt for more than 65,535 keys");
        }

        // sign inner

        let mut to_be_encrypted = super::signature::sign(fingerprint, content).to_vec();
        to_be_encrypted.extend(content);

        // encrypt

        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
        let content_key = chacha20poly1305::XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

        let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&content_key);

        let encrypted_content = match content_cipher.encrypt(&nonce, to_be_encrypted.as_ref()) {
            Ok(ec) => ec,
            Err(_) => return Err("failed to encrypt content"),
        };

        // per-recipient encryption

        let mut keys: Vec<u8> = vec![];

        let (e_priv_key, ot_pub_key) = super::generate_exchange_keys();
        let e_priv_key = x25519_dalek::StaticSecret::from(e_priv_key);

        let content_key_as_bytes: [u8; 32] = match content_key.try_into() {
            Ok(v) => v,
            Err(_) => return Err("failed to convert content key to fixed bytes"),
        };

        for pub_key in pub_keys.chunks(32) {
            let pub_key_as_bytes: [u8; 32] = match pub_key.try_into() {
                Ok(v) => v,
                Err(_) => return Err("failed to convert pub key to fixed bytes"),
            };

            let shared_secret = e_priv_key
                .diffie_hellman(&x25519_dalek::PublicKey::from(pub_key_as_bytes))
                .to_bytes();

            let encrypted_content_key =
                super::bytes_32::encrypt(&shared_secret, &content_key_as_bytes);
            keys.extend(encrypted_content_key);
        }

        // keys count header is first 2 bytes
        let mut out = ((keys.len() / 32) as u16).to_be_bytes().to_vec();
        out.extend(keys);

        // fist 32 bytes after keys
        out.extend(ot_pub_key);
        // next 24 bytes
        out.extend(nonce);
        // all remaining bytes
        out.extend(encrypted_content);

        Ok(out)
    }

    pub fn extract_components_for_key_position(
        encrypted_content: &[u8],
        position: u16,
    ) -> Result<(Vec<u8>, [u8; ENCRYPTED_KEY_LENGTH]), &'static str> {
        let key_header_bytes: [u8; 2] = match encrypted_content[0..2].try_into() {
            Ok(b) => b,
            Err(_) => return Err("failed to convert keys header to bytes"),
        };

        let key_count = u16::from_be_bytes(key_header_bytes) as usize;
        let keys_end = key_count * ENCRYPTED_KEY_LENGTH + 2;

        let encrypted_content_key = match encrypted_content
            [(2 + position as usize)..(ENCRYPTED_KEY_LENGTH + 2 + position as usize)]
            .try_into()
        {
            Ok(b) => b,
            Err(_) => return Err("failed to convert content key to bytes"),
        };

        Ok((
            encrypted_content[keys_end..].to_vec(),
            encrypted_content_key,
        ))
    }

    pub fn decrypt(
        verifying_key: Option<&[u8; 32]>,
        priv_key: [u8; 32],

        encrypted_key: &[u8; ENCRYPTED_KEY_LENGTH],
        encrypted_content: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let pub_key: [u8; 32] = match encrypted_content[0..32].try_into() {
            Ok(key) => key,
            Err(_) => return Err("failed to convert pub key to fixed bytes bytes"),
        };

        let nonce: [u8; NONCE_SIZE] = match encrypted_content[32..32 + NONCE_SIZE].try_into() {
            Ok(key) => key,
            Err(_) => return Err("failed to convert nonce to fixed bytes bytes"),
        };

        let priv_key = x25519_dalek::StaticSecret::from(priv_key);
        let shared_secret = priv_key.diffie_hellman(&pub_key.into()).to_bytes();

        let content_key = super::bytes_32::decrypt(&shared_secret, encrypted_key);

        let content_cipher = chacha20poly1305::XChaCha20Poly1305::new(&content_key.into());

        match content_cipher.decrypt(&nonce.into(), &encrypted_content[32 + NONCE_SIZE..]) {
            Ok(content) => match verifying_key {
                Some(verifying_key) => {
                    let signature_as_bytes: [u8; 64] = match content[0..64].try_into() {
                        Ok(v) => v,
                        Err(_) => return Err("failed to convert signature to fixed bytes"),
                    };

                    let content = content[64..].to_vec();

                    match super::signature::verify(&signature_as_bytes, verifying_key, &content) {
                        Ok(_) => Ok(content),
                        Err(_) => Err("failed to verify signature"),
                    }
                }
                None => Ok(content[64..].to_vec()),
            },
            Err(_) => return Err("failed to decrypt content"),
        }
    }
}
