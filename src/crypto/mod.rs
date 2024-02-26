/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use chacha20::cipher::{generic_array::GenericArray, typenum};
use chacha20poly1305::{aead::Aead, XChaCha20Poly1305};
use ed25519_dalek::{Signer, Verifier};

use classic_mceliece_rust::{
    CRYPTO_CIPHERTEXTBYTES as KEM_CIPHERTEXT_SIZE, CRYPTO_SECRETKEYBYTES as KEM_SECRET_KEY_SIZE,
};

mod modes;
pub use modes::*;

mod decrypt;
pub use decrypt::*;

mod encrypt;
pub use encrypt::*;

mod extract;
pub use extract::*;

const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

/// generates fingerprints and verifying keys for signing.
///
/// ```rust
/// use rgp::generate_fingerprint;
///
/// let (fingerprint, verifier) = generate_fingerprint();
///
/// assert_eq!(fingerprint.len(), 32);
/// assert_eq!(verifier.len(), 32);
/// ```
pub fn generate_fingerprint() -> ([u8; 32], [u8; 32]) {
    let fingerprint = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    (
        fingerprint.to_bytes(),
        fingerprint.verifying_key().to_bytes(),
    )
}

#[inline(always)]
fn usize_to_bytes(val: usize) -> (usize, [u8; 9]) {
    let mut out = [0u8; 9];

    if val < 128 {
        out[0] = ((val << 1) | 1) as u8;

        (1, out)
    } else {
        match val {
            128..=255 => {
                out[0] = 0 << 2;
                out[1] = val as u8;

                (2, out)
            }
            256..=65_535 => {
                out[0] = 1 << 2;
                out[1..3].copy_from_slice(&(val as u16).to_be_bytes());

                (3, out)
            }
            65_536..=4_294_967_295 => {
                out[0] = 2 << 2;
                out[1..5].copy_from_slice(&(val as u32).to_be_bytes());

                (5, out)
            }
            _ => {
                out[0] = 3 << 2;
                out[1..9].copy_from_slice(&(val as u64).to_be_bytes());

                (9, out)
            }
        }
    }
}

#[inline(always)]
fn bytes_to_usize(bytes: &[u8]) -> (usize, usize) {
    let first_byte = bytes[0];

    if (first_byte & 0b00000001) != 0 {
        (1, (first_byte >> 1) as usize)
    } else {
        match (first_byte >> 2) & 0b00000011 {
            0 => (2, bytes[1] as usize),
            1 => (
                3,
                u16::from_be_bytes(bytes[1..3].try_into().unwrap()) as usize,
            ),
            2 => (
                5,
                u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
            ),
            3 => (
                9,
                u64::from_be_bytes(bytes[1..9].try_into().unwrap()) as usize,
            ),
            _ => unreachable!(),
        }
    }
}

/// signs content.
#[inline(always)]
fn sign(fingerprint: &[u8; 32], content: &[u8]) -> [u8; 64] {
    let fingerprint = ed25519_dalek::SigningKey::from_bytes(fingerprint);
    let signature = fingerprint.sign(content);

    signature.to_bytes()
}

/// signs and encrypts content.
fn base_encrypt(
    fingerprint: [u8; 32],
    nonce: &GenericArray<u8, typenum::U24>,
    key: &GenericArray<u8, typenum::U32>,
    content: &mut Vec<u8>,
) -> Result<Vec<u8>, &'static str> {
    use chacha20poly1305::KeyInit;

    let signature = sign(&fingerprint, &content);
    content.extend(signature);

    let content_cipher = XChaCha20Poly1305::new(key);
    match content_cipher.encrypt(nonce, content.as_ref()) {
        Ok(encrypted_content) => Ok(encrypted_content),
        Err(_) => Err("failed to encrypt content"),
    }
}

/// verifies signatures.
#[inline(always)]
fn verify(signature: &[u8; 64], verifier: &[u8; 32], content: &[u8]) -> Result<(), &'static str> {
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    let verifier = match ed25519_dalek::VerifyingKey::from_bytes(verifier) {
        Ok(vk) => vk,
        Err(_) => return Err("failed to convert verifying key"),
    };

    match verifier.verify(content, &signature) {
        Ok(_) => Ok(()),
        Err(_) => return Err("failed to verify signature"),
    }
}

/// decrypts and verifies content.
fn base_decrypt(
    verifier: Option<&[u8; 32]>,
    nonce: &GenericArray<u8, typenum::U24>,
    key: GenericArray<u8, typenum::U32>,
    encrypted_content: &[u8],
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let content_cipher = {
        use chacha20poly1305::KeyInit;
        XChaCha20Poly1305::new(&key)
    };

    match content_cipher.decrypt(nonce, encrypted_content) {
        Ok(mut content) => {
            let signature = content.split_off(content.len() - SIGNATURE_SIZE);

            match verifier {
                Some(verifier) => {
                    let signature_as_bytes: [u8; SIGNATURE_SIZE] = match signature.try_into() {
                        Ok(v) => v,
                        Err(_) => return Err("failed to convert signature to bytes"),
                    };

                    verify(&signature_as_bytes, verifier, &content)?;
                    Ok((content, key.into()))
                }
                None => Ok((content, key.into())),
            }
        }
        Err(_) => return Err("failed to decrypt content"),
    }
}
