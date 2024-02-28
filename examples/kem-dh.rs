/*
Copyright (c) 2024 Ordinary Labs

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use std::error::Error;
use std::fs::{remove_file, File, OpenOptions};
use std::io::Write;

use rgp::{
    decrypt, encrypt, extract_components_mut, generate_dh_keys, generate_fingerprint,
    generate_kem_keys, Components, Decrypt, Encrypt, KemKeyReader,
};

pub fn main() -> Result<(), Box<dyn Error>> {
    let (fingerprint, verifier) = generate_fingerprint();

    let (recipient_kem_secret_key, recipient_kem_pub_key) = generate_kem_keys();

    let (sender_dh_priv_key, sender_dh_pub_key) = generate_dh_keys();
    let (recipient_dh_priv_key, recipient_dh_pub_key) = generate_dh_keys();

    // 5mb
    let content = vec![0u8; 5_000_000];

    // create pub key file and open in append mode
    let mut pub_keys_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("example_kem_dh_pub_keys")?;

    // write first recipient's pub keys to pub key file
    pub_keys_file.write_all(&recipient_kem_pub_key)?;
    pub_keys_file.write_all(&recipient_dh_pub_key)?;
    pub_keys_file.flush()?;

    // write additional 50 recipient keys to file
    for _ in 0..50 {
        let (_, kem_pub_key) = generate_kem_keys();
        let (_, dh_pub_key) = generate_dh_keys();

        pub_keys_file.write_all(&kem_pub_key)?;
        pub_keys_file.write_all(&dh_pub_key)?;
        pub_keys_file.flush()?;
    }

    // initialize public key reader for McEliece pub key file
    let key_reader =
        KemKeyReader::new_dh_hybrid(sender_dh_priv_key, File::open("example_kem_dh_pub_keys")?);

    // encrypt message for all recipients
    let (mut encrypted_content, content_key) =
        encrypt(fingerprint, content.clone(), Encrypt::Kem(key_reader))?;

    // extract encrypted content key and ciphertext at position 0
    if let Components::Kem(encrypted_key, ciphertext, is_hybrid) =
        extract_components_mut(0, &mut encrypted_content)
    {
        if is_hybrid {
            // decrypt message with encrypted content key ciphertext
            let (decrypted_content, decrypted_content_key) = decrypt(
                Some(&verifier),
                &encrypted_content,
                Decrypt::Kem(
                    encrypted_key,
                    ciphertext,
                    recipient_kem_secret_key,
                    Some((sender_dh_pub_key, recipient_dh_priv_key)),
                ),
            )?;

            assert_eq!(decrypted_content, content);
            assert_eq!(decrypted_content_key, content_key);
        }
    };

    remove_file("example_kem_dh_pub_keys")?;

    Ok(())
}
