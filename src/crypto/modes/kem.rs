/*
RGP was built to enable E2EE for a broad range of applications

Copyright (C) 2024  Ordinary Labs, LLC

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

use super::super::{
    base_decrypt, base_encrypt, bytes_to_usize, usize_to_bytes, KEY_SIZE, NONCE_SIZE,
};

use std::io::{BufReader, Read};
#[cfg(feature = "multi-thread")]
use std::sync::mpsc::channel;

use blake2::digest::{FixedOutput, Mac};
use chacha20::{
    cipher::{generic_array::GenericArray, typenum, StreamCipher},
    XChaCha20,
};
use chacha20poly1305::{AeadCore, XChaCha20Poly1305};
use classic_mceliece_rust::{
    decapsulate, encapsulate, keypair as kem_keypair, Ciphertext, PublicKey as KemPublicKey,
    SecretKey as KemSecretKey, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
};
use x25519_dalek::StaticSecret;

pub const KEM_CIPHERTEXT_SIZE: usize = CRYPTO_CIPHERTEXTBYTES;
pub const KEM_PUB_KEY_SIZE: usize = CRYPTO_PUBLICKEYBYTES;
pub const KEM_SECRET_KEY_SIZE: usize = CRYPTO_SECRETKEYBYTES;

/// #
/// **ENCRYPTED FORMAT:**
/// - nonce = 24 bytes
/// - keys count
///     - IF 0..=127
///         - is single byte = 1 bit (set)
///         - count = 7 bits
///     - ELSE
///         - is single byte = 1 bit (unset)
///         - int size = 2 bits
///         - count = 8-64 bits
/// - encrypted copies of content key + ciphertext = pub_keys.len() * (32 bytes + 96 bytes)
/// - encrypted content = content.len()
/// - signature = 64 bytes (encrypted along with the content)
/// - Poly1305 MAC = 16 bytes
/// - mode = 1 byte (set to KEM_MODE)
///
/// **PROCESS:**
/// 1. Generate one-time components
///     - nonce
///     - content key
/// 2. Sign plaintext to generate content signature
/// 3. Encrypt plaintext and content signature with content key
/// 4. Encrypt content key for all recipients
///     - Generate ciphertext and encapsulated key with recipient's public key
///     - Encrypt content key with encapsulated key
///     - Append ciphertext to encrypted content key
pub const KEM_MODE: u8 = 5;

/// #
/// **ENCRYPTED FORMAT:**
/// - nonce = 24 bytes
/// - keys count
///     - IF 0..=127
///         - is single byte = 1 bit (set)
///         - count = 7 bits
///     - ELSE
///         - is single byte = 1 bit (unset)
///         - int size = 2 bits
///         - count = 8-64 bits
/// - encrypted copies of content key + ciphertext = pub_keys.len() * (32 bytes + 96 bytes)
/// - encrypted content = content.len()
/// - signature = 64 bytes (encrypted along with the content)
/// - Poly1305 MAC = 16 bytes
/// - mode = 1 byte (set to KEM_WITH_DH_HYBRID_MODE)
///
/// **PROCESS:**
/// 1. Generate one-time components
///     - nonce
///     - content key
/// 2. Sign plaintext to generate content signature
/// 3. Encrypt plaintext and content signature with content key
/// 4. Encrypt content key for all recipients
///     - Generate ciphertext and encapsulated key with recipient's public key for `Kem`
///     - Generate shared secret with recipient's public key and sender's private key for `Dh`
///     - HMAC the `Kem` encapsulated key with the `Dh` shared secret as the key
///     - Encrypt content key with the HMAC result
///     - Append ciphertext to encrypted content key
pub const KEM_WITH_DH_HYBRID_MODE: u8 = 6;

/// generates `Kem` pub/priv key pairs.
///
///```rust
/// use rgp::generate_kem_keys;
///
/// let (secret_key, pub_key) = generate_kem_keys();
///
/// assert_eq!(secret_key.len(), 6492);
/// assert_eq!(pub_key.len(), 261120);
///```
pub fn generate_kem_keys() -> ([u8; KEM_SECRET_KEY_SIZE], [u8; KEM_PUB_KEY_SIZE]) {
    let mut rng = rand::thread_rng();

    let mut public_key_buf = [0u8; KEM_PUB_KEY_SIZE];
    let mut secret_key_buf = [0u8; KEM_SECRET_KEY_SIZE];

    let (pub_key, secret_key) = kem_keypair(&mut public_key_buf, &mut secret_key_buf, &mut rng);

    (*secret_key.as_array(), *pub_key.as_array())
}

/// for reading a large volume of Classic McEliece public keys
pub struct KemKeyReader<R: Read> {
    pub reader: BufReader<R>,

    /// for Kem + Dh hybrid
    pub dh_priv_key: Option<[u8; KEY_SIZE]>,
}

impl<R: Read> KemKeyReader<R> {
    /// public key reader with a buffer size of 261120.
    ///
    /// for files that contain only McEliece public keys all in one line.
    pub fn new(source: R) -> Self {
        KemKeyReader {
            reader: BufReader::with_capacity(KEM_PUB_KEY_SIZE, source),
            dh_priv_key: None,
        }
    }

    /// public key reader with a buffer size of 261120 + 32.
    ///
    /// for files that contain McEliece public paired with their
    /// Diffie-Hellman counterparts (i.e Vec<...[u8; ...mc_pub, ...dh_pub]>)
    pub fn new_dh_hybrid(dh_priv_key: [u8; KEY_SIZE], source: R) -> Self {
        KemKeyReader {
            reader: BufReader::with_capacity(KEM_PUB_KEY_SIZE + KEY_SIZE, source),
            dh_priv_key: Some(dh_priv_key),
        }
    }
}

/// per-recipient content key encryption.
#[inline(always)]
fn kem_encrypt_keys<R: Read>(
    key_reader: &mut KemKeyReader<R>,
    nonce: &GenericArray<u8, typenum::U24>,
    content_key: &GenericArray<u8, typenum::U32>,
) -> ((usize, [u8; 9]), Vec<u8>) {
    use chacha20::cipher::KeyIvInit;

    let mut rng = rand::thread_rng();

    let mut key_pos = 0;
    let mut out = vec![];

    // Kem + Dh hybrid
    if let Some(dh_priv_key) = key_reader.dh_priv_key {
        let dh_priv_key = StaticSecret::from(dh_priv_key);

        let mut buf = [0u8; KEM_PUB_KEY_SIZE + KEY_SIZE];

        while let Ok(_) = key_reader.reader.read_exact(&mut buf) {
            let kem_pub_key = buf[0..KEM_PUB_KEY_SIZE].try_into().unwrap();
            let kem_pub_key = KemPublicKey::from(&kem_pub_key);

            let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
            let (kem_ciphertext, kem_shared_secret) =
                encapsulate(&kem_pub_key, &mut kem_shared_secret_buf, &mut rng);

            let mut key = GenericArray::from(*kem_shared_secret.as_array());

            let dh_pub_key: [u8; KEY_SIZE] = buf[KEM_PUB_KEY_SIZE..KEM_PUB_KEY_SIZE + KEY_SIZE]
                .try_into()
                .unwrap();
            let dh_shared_secret = dh_priv_key.diffie_hellman(&dh_pub_key.into()).to_bytes();

            // HMAC the KEM shared secret with the Diffie-Hellman shared secret
            key = blake2::Blake2sMac256::new_from_slice(&dh_shared_secret)
                .unwrap()
                .chain_update(&key)
                .finalize_fixed();

            let mut key_cipher = XChaCha20::new(&key, nonce);

            let mut content_key = content_key.clone();
            key_cipher.apply_keystream(&mut content_key);

            out.extend(content_key);
            out.extend(kem_ciphertext.as_array());

            key_pos += 1;
        }
    } else {
        // raw Kem

        let mut buf = [0u8; KEM_PUB_KEY_SIZE];

        while let Ok(_) = key_reader.reader.read_exact(&mut buf) {
            let kem_pub_key = KemPublicKey::from(&buf);

            let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
            let (kem_ciphertext, kem_shared_secret) =
                encapsulate(&kem_pub_key, &mut kem_shared_secret_buf, &mut rng);

            let key = GenericArray::from(*kem_shared_secret.as_array());

            let mut key_cipher = XChaCha20::new(&key, nonce);

            let mut content_key = content_key.clone();
            key_cipher.apply_keystream(&mut content_key);

            out.extend(content_key);
            out.extend(kem_ciphertext.as_array());

            key_pos += 1;
        }
    }

    let header = usize_to_bytes(key_pos);

    (header, out)
}

/// kem encryption.
#[inline(always)]
pub fn kem_encrypt<'a, R: Read>(
    fingerprint: [u8; 32],
    mut content: Vec<u8>,
    key_reader: &mut KemKeyReader<R>,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
    let mut out = nonce.to_vec();

    use chacha20poly1305::KeyInit;
    let key = XChaCha20Poly1305::generate_key(&mut rand_core::OsRng);

    #[cfg(feature = "multi-thread")]
    let (sender, receiver) = channel();

    #[cfg(feature = "multi-thread")]
    rayon::spawn(move || {
        let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content);
        sender.send(encrypted_content).unwrap();
    });

    let ((size, bytes), keys) = kem_encrypt_keys(key_reader, &nonce, &key);
    out.extend_from_slice(&bytes[..size]);
    out.extend(keys);

    #[cfg(feature = "multi-thread")]
    let encrypted_content = receiver.recv().unwrap()?;
    #[cfg(not(feature = "multi-thread"))]
    let encrypted_content = base_encrypt(fingerprint, &nonce, &key, &mut content)?;

    out.extend(encrypted_content);

    if key_reader.dh_priv_key.is_some() {
        out.push(KEM_WITH_DH_HYBRID_MODE);
    } else {
        out.push(KEM_MODE);
    }

    Ok((out, key.into()))
}

/// kem decryption.
#[inline(always)]
pub fn kem_decrypt(
    verifier: Option<&[u8; 32]>,
    encrypted_content: &[u8],

    mut encrypted_key: [u8; KEY_SIZE],
    ciphertext: [u8; KEM_CIPHERTEXT_SIZE],
    mut secret_key: [u8; KEM_SECRET_KEY_SIZE],
    dh_components: Option<([u8; KEY_SIZE], [u8; KEY_SIZE])>,
) -> Result<(Vec<u8>, [u8; KEY_SIZE]), &'static str> {
    let nonce = &GenericArray::<u8, typenum::U24>::from_slice(&encrypted_content[0..NONCE_SIZE]);
    let encrypted_content = &encrypted_content[NONCE_SIZE..];

    let secret_key = KemSecretKey::from(&mut secret_key);
    let ciphertext = Ciphertext::from(ciphertext);

    let mut kem_shared_secret_buf = [0u8; KEY_SIZE];
    let mut key = GenericArray::from(
        *decapsulate(&ciphertext, &secret_key, &mut kem_shared_secret_buf).as_array(),
    );

    if let Some((pub_key, priv_key)) = dh_components {
        let priv_key = StaticSecret::from(priv_key);
        let shared_secret = priv_key.diffie_hellman(&pub_key.into()).to_bytes();

        // HMAC the KEM shared secret with the Diffie-Hellman shared secret
        key = blake2::Blake2sMac256::new_from_slice(&shared_secret)
            .unwrap()
            .chain_update(&key)
            .finalize_fixed();
    }

    let mut key_cipher = {
        use chacha20::cipher::KeyIvInit;
        XChaCha20::new(&key, nonce)
    };

    key_cipher.apply_keystream(&mut encrypted_key);

    base_decrypt(verifier, nonce, encrypted_key.into(), encrypted_content)
}

/// extract kem components.
#[inline(always)]
pub fn kem_extract(
    position: usize,
    encrypted_content: &mut Vec<u8>,
) -> ([u8; KEY_SIZE], [u8; KEM_CIPHERTEXT_SIZE]) {
    let (keys_count_size, keys_count) =
        bytes_to_usize(&encrypted_content[NONCE_SIZE..NONCE_SIZE + 9]);

    let keys_start = NONCE_SIZE + keys_count_size;
    let encrypted_key_start = keys_start + (position as usize * (KEY_SIZE + KEM_CIPHERTEXT_SIZE));

    let content_key: [u8; KEY_SIZE] = encrypted_content
        [encrypted_key_start..encrypted_key_start + KEY_SIZE]
        .try_into()
        .unwrap();

    let ciphertext: [u8; KEM_CIPHERTEXT_SIZE] = encrypted_content
        [encrypted_key_start + KEY_SIZE..encrypted_key_start + (KEY_SIZE + KEM_CIPHERTEXT_SIZE)]
        .try_into()
        .unwrap();

    let encrypted_content_start = keys_start + (keys_count * (KEY_SIZE + KEM_CIPHERTEXT_SIZE));

    encrypted_content.copy_within(encrypted_content_start.., NONCE_SIZE);
    encrypted_content.truncate(
        encrypted_content.len()
            - keys_count_size
            - (keys_count * (KEY_SIZE + KEM_CIPHERTEXT_SIZE))
            - 1,
    );

    (content_key, ciphertext)
}

#[cfg(test)]
mod tests {
    use std::fs::{remove_file, File, OpenOptions};
    use std::io::Write;

    use super::{kem_decrypt, kem_encrypt, kem_extract, KemKeyReader};

    #[test]
    fn test_kem() {
        let (fingerprint, verifier) = crate::generate_fingerprint();

        let (secret_key, pub_key) = crate::generate_kem_keys();

        let content = vec![0u8; 1024];

        let mut pub_keys_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("test_kem_pub_keys")
            .unwrap();

        pub_keys_file.write_all(&pub_key).unwrap();
        pub_keys_file.flush().unwrap();

        let mut key_reader = KemKeyReader::new(File::open("test_kem_pub_keys").unwrap());

        let (mut encrypted_content, content_key) =
            kem_encrypt(fingerprint, content.clone(), &mut key_reader).unwrap();

        let (encrypted_key, ciphertext) = kem_extract(0, &mut encrypted_content);

        let (decrypted_content, decrypted_content_key) = kem_decrypt(
            Some(&verifier),
            &encrypted_content,
            encrypted_key,
            ciphertext,
            secret_key,
            None,
        )
        .unwrap();

        assert_eq!(content, decrypted_content);
        assert_eq!(content_key, decrypted_content_key);

        remove_file("test_kem_pub_keys").unwrap()
    }

    #[test]
    fn test_kem_with_dh_hybrid() {
        let (fingerprint, verifier) = crate::generate_fingerprint();

        let (kem_secret_key, kem_pub_key) = crate::generate_kem_keys();

        let (sender_dh_priv_key, sender_dh_pub_key) = crate::generate_dh_keys();
        let (recipient_dh_priv_key, recipient_dh_pub_key) = crate::generate_dh_keys();

        let content = vec![0u8; 1024];

        let mut pub_keys_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("test_kem_with_dh_hybrid_pub_keys")
            .unwrap();

        pub_keys_file.write_all(&kem_pub_key).unwrap();
        pub_keys_file.write_all(&recipient_dh_pub_key).unwrap();
        pub_keys_file.flush().unwrap();

        let mut key_reader = KemKeyReader::new_dh_hybrid(
            sender_dh_priv_key,
            File::open("test_kem_with_dh_hybrid_pub_keys").unwrap(),
        );

        let (mut encrypted_content, content_key) =
            kem_encrypt(fingerprint, content.clone(), &mut key_reader).unwrap();

        let (encrypted_key, ciphertext) = kem_extract(0, &mut encrypted_content);

        let (decrypted_content, decrypted_content_key) = kem_decrypt(
            Some(&verifier),
            &encrypted_content,
            encrypted_key,
            ciphertext,
            kem_secret_key,
            Some((sender_dh_pub_key, recipient_dh_priv_key)),
        )
        .unwrap();

        assert_eq!(content, decrypted_content);
        assert_eq!(content_key, decrypted_content_key);

        remove_file("test_kem_with_dh_hybrid_pub_keys").unwrap()
    }
}
