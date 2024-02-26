/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use super::super::{
    base_decrypt, base_encrypt, bytes_to_usize, usize_to_bytes, KEY_SIZE, NONCE_SIZE,
};

use blake2::digest::{
    generic_array::{typenum, GenericArray},
    FixedOutput, Mac,
};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305};

/// #
/// **ENCRYPTED FORMAT:**
/// - nonce = 24 bytes
/// - iteration
///     - IF 0..=127
///         - is single byte = 1 bit (set)
///         - iteration = 7 bits
///     - ELSE
///         - is single byte = 1 bit (unset)
///         - int size = 2 bits
///         - iteration = 8-64 bits
/// - encrypted content = content.len()
/// - signature = 64 bytes (encrypted along with the content)
/// - Poly1305 MAC = 16 bytes
/// - mode = 1 byte (set to HMAC_MODE)
///
/// **PROCESS:**
/// 1. Generate nonce
/// 2. Hash the provided components
/// 3. Sign plaintext to generate content signature
/// 4. Encrypt plaintext and content signature with the hashed key
pub const HMAC_MODE: u8 = 1;

/// hmac encryption.
#[inline(always)]
pub fn hmac_encrypt(
    fingerprint: [u8; 32],
    mut content: Vec<u8>,
    hmac_key: [u8; KEY_SIZE],
    hmac_value: [u8; KEY_SIZE],
    iteration: usize,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    let key = blake2::Blake2sMac256::new_from_slice(&hmac_key)
        .unwrap()
        .chain_update(&hmac_value)
        .finalize_fixed();

    let (size, bytes) = usize_to_bytes(iteration);
    out.extend_from_slice(&bytes[..size]);

    let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content)?;
    out.extend(encrypted_content);

    out.push(HMAC_MODE);

    Ok((out, key.into()))
}

/// hmac decryption.
#[inline(always)]
pub fn hmac_decrypt(
    verifier: Option<&[u8; 32]>,
    encrypted_content: &[u8],

    hmac_key: [u8; KEY_SIZE],
    hmac_value: [u8; KEY_SIZE],
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = &GenericArray::<u8, typenum::U24>::from_slice(&encrypted_content[0..NONCE_SIZE]);
    let encrypted_content = &encrypted_content[NONCE_SIZE..];

    let key = blake2::Blake2sMac256::new_from_slice(&hmac_key)
        .unwrap()
        .chain_update(&hmac_value)
        .finalize_fixed();

    base_decrypt(verifier, nonce, key.into(), encrypted_content)
}

/// extract hmac components.
#[inline(always)]
pub fn hmac_extract(encrypted_content: &mut Vec<u8>) -> usize {
    let (itr_size, itr) = bytes_to_usize(&encrypted_content[NONCE_SIZE..NONCE_SIZE + 9]);

    encrypted_content.copy_within(NONCE_SIZE + itr_size.., NONCE_SIZE);
    encrypted_content.truncate(encrypted_content.len() - itr_size - 1);

    itr
}

#[cfg(test)]
mod tests {
    use super::{hmac_decrypt, hmac_encrypt, hmac_extract};

    #[test]
    fn test_hmac() {
        let (fingerprint, verifier) = crate::generate_fingerprint();
        let (hmac_key, hmac_value) = crate::generate_dh_keys();

        let content = vec![0u8; 1024];

        let (mut encrypted_content, content_key) =
            hmac_encrypt(fingerprint, content.clone(), hmac_key, hmac_value, 42).unwrap();

        let itr = hmac_extract(&mut encrypted_content);

        assert_eq!(itr, 42);

        let (decrypted_content, decrypted_content_key) =
            hmac_decrypt(Some(&verifier), &encrypted_content, hmac_key, hmac_value).unwrap();

        assert_eq!(content, decrypted_content);
        assert_eq!(content_key, decrypted_content_key);
    }
}
