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

pub const HMAC_MODE: u8 = 1;

/// hmac encryption.
#[inline(always)]
pub fn hmac_encrypt(
    fingerprint: [u8; 32],
    nonce: GenericArray<u8, typenum::U24>,
    out: &mut Vec<u8>,
    mut content: Vec<u8>,
    hmac_key: [u8; KEY_SIZE],
    hmac_value: [u8; KEY_SIZE],
    iteration: usize,
) -> Result<[u8; KEY_SIZE], &'static str> {
    let key = blake2::Blake2sMac256::new_from_slice(&hmac_key)
        .unwrap()
        .chain_update(&hmac_value)
        .finalize_fixed();

    let (size, bytes) = usize_to_bytes(iteration);
    out.extend_from_slice(&bytes[..size]);

    let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content)?;
    out.extend(encrypted_content);

    Ok(key.into())
}

/// hmac decryption.
#[inline(always)]
pub fn hmac_decrypt(
    verifier: Option<&[u8; 32]>,
    nonce: &GenericArray<u8, typenum::U24>,
    encrypted_content: &[u8],

    hmac_key: [u8; KEY_SIZE],
    hmac_value: [u8; KEY_SIZE],
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
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
    encrypted_content.truncate(encrypted_content.len() - itr_size);

    itr
}
