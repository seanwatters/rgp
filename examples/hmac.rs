/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use rgp::{
    decrypt, encrypt, extract_components_mut, generate_fingerprint, Components, Decrypt, Encrypt,
};

pub fn main() -> Result<(), &'static str> {
    let (fingerprint, verifier) = generate_fingerprint();

    // use actually secret values
    let hmac_key = [0u8; 32];
    let hmac_value = [1u8; 32];

    // 5mb
    let content = vec![0u8; 5_000_000];

    // encrypt message keyed hash result
    let (mut encrypted_content, content_key) = encrypt(
        fingerprint,
        content.clone(),
        Encrypt::Hmac(hmac_key, hmac_value, 42),
    )?;

    // extract iterator
    if let Components::Hmac(itr) = extract_components_mut(0, &mut encrypted_content) {
        assert_eq!(itr, 42);

        // decrypt message with keyed hash result mode
        let (decrypted_content, hashed_content_key) = decrypt(
            Some(&verifier),
            &encrypted_content,
            Decrypt::Hmac(hmac_key, hmac_value),
        )?;

        assert_eq!(decrypted_content, content);
        assert_eq!(hashed_content_key, content_key);
    };

    Ok(())
}
