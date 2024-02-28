/*
Copyright (c) 2024 Ordinary Labs

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
    let (mut encrypted_content, _) = encrypt(
        fingerprint,
        content.clone(),
        Encrypt::Session(session_key, false),
    )?;

    if let Components::Session(_) = extract_components_mut(0, &mut encrypted_content) {
        // decrypt message with session key
        let (decrypted_content, _) = decrypt(
            Some(&verifier),
            &encrypted_content,
            Decrypt::Session(session_key, None),
        )?;

        assert_eq!(decrypted_content, content);
    };

    Ok(())
}
