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

    // use an actually secret key
    let session_key = [0u8; 32];

    // 5mb
    let content = vec![0u8; 5_000_000];

    // encrypt message with a session key
    let (mut encrypted_content, content_key) = encrypt(
        fingerprint,
        content.clone(),
        Encrypt::Session(session_key, true),
    )?;

    // extract encrypted key
    if let Components::Session(encrypted_key) = extract_components_mut(0, &mut encrypted_content) {
        // decrypt message with session key
        let (decrypted_content, decrypted_key) = decrypt(
            Some(&verifier),
            &encrypted_content,
            Decrypt::Session(session_key, encrypted_key),
        )?;

        assert_eq!(decrypted_content, content);
        assert_eq!(decrypted_key, content_key);
    };

    Ok(())
}
