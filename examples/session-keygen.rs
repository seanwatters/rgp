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
