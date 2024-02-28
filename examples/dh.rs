/*
RGP was built to enable E2EE for a broad range of applications

Copyright (C) 2024 Ordinary Labs, LLC

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

use rgp::{
    decrypt, encrypt, extract_components_mut, generate_dh_keys, generate_fingerprint, Components,
    Decrypt, Encrypt,
};

pub fn main() -> Result<(), &'static str> {
    let (fingerprint, verifier) = generate_fingerprint();

    let (sender_priv_key, sender_pub_key) = generate_dh_keys();
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
        Encrypt::Dh(sender_priv_key, &pub_keys, None),
    )?;

    // extract encrypted content key at position 0
    if let Components::Dh(encrypted_key, _) = extract_components_mut(0, &mut encrypted_content) {
        // decrypt message with encrypted content key
        let (decrypted_content, decrypted_content_key) = decrypt(
            Some(&verifier),
            &encrypted_content,
            Decrypt::Dh(encrypted_key, sender_pub_key, receiver_priv_key, None),
        )?;

        assert_eq!(decrypted_content, content);
        assert_eq!(decrypted_content_key, content_key);
    };

    Ok(())
}
