/*
Copyright (c) 2024 Ordinary Labs

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use rgp::{
    decrypt, encrypt, extract_components_mut, generate_dh_keys, generate_fingerprint, Components,
    Decrypt, Encrypt,
};

pub fn main() -> Result<(), &'static str> {
    let (fingerprint, verifier) = generate_fingerprint();

    let (sender_priv_key, sender_pub_key) = generate_dh_keys();
    // use an actually secret key
    let hmac_key = [0u8; 32];

    let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();

    let mut pub_keys = vec![receiver_pub_key];

    // 5mb
    let content = vec![0u8; 5_000_000];

    // add another 10,000 recipients
    for _ in 0..10_000 {
        let (_, pub_key) = generate_dh_keys();
        pub_keys.push(pub_key)
    }

    // encrypt message for all recipients
    let (mut encrypted_content, content_key) = encrypt(
        fingerprint,
        content.clone(),
        Encrypt::Dh(sender_priv_key, &pub_keys, Some(hmac_key)),
    )?;

    // extract encrypted content key and whether it was encrypted with hmac at position 0
    if let Components::Dh(encrypted_key, with_hmac) =
        extract_components_mut(0, &mut encrypted_content)
    {
        if with_hmac {
            // decrypt message with encrypted content key and hmac key
            let (decrypted_content, decrypted_content_key) = decrypt(
                Some(&verifier),
                &encrypted_content,
                Decrypt::Dh(
                    encrypted_key,
                    sender_pub_key,
                    receiver_priv_key,
                    Some(hmac_key),
                ),
            )?;

            assert_eq!(decrypted_content, content);
            assert_eq!(decrypted_content_key, content_key);
        }
    };

    Ok(())
}
