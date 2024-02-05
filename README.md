# Ordinal Crypto 🔐

[![ci](https://github.com//ordinarylabs/ordinal-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com//ordinarylabs/ordinal-crypto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/ordinal_crypto.svg)](https://crates.io/crates/ordinal_crypto)
[![docs.rs](https://docs.rs/ordinal_crypto/badge.svg)](https://docs.rs/ordinal_crypto/)
[![license](https://img.shields.io/github/license/ordinarylabs/ordinal-crypto.svg)](https://github.com/ordinarylabs/ordinal-crypto/blob/main/LICENSE)
[![dependency status](https://deps.rs/repo/github/ordinarylabs/ordinal-crypto/status.svg)](https://deps.rs/repo/github/ordinarylabs/ordinal-crypto)

The cryptography library for the Ordinal Platform

## Usage

```rust
let (our_priv_key, our_pub_key) = ordinal_crypto::generate_exchange_keys();
let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();

let mut pub_keys = vec![our_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// 50,000 recipients
for _ in 0..50_000 {
    let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
    pub_keys.push(pub_key)
}

let mut encrypted_content =
    ordinal_crypto::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();

let encrypted_content =
    ordinal_crypto::content::extract_content_for_key_position(&mut encrypted_content, 0)
        .unwrap();

let decrypted_content = ordinal_crypto::content::decrypt(
    Some(&verifying_key),
    our_priv_key,
    &encrypted_content,
)
.unwrap();

assert_eq!(decrypted_content, content);
```

## Format

- nonce = 24 bytes
- one-time public key = 32 bytes
- keys count header = 2-9 bytes
    - size = 1 byte (1 | 2 | 4 | 8)
    - big endian bytes = 1-8 bytes
- encrypted keys = pub_keys.len() * 32 bytes
- inner signature = 64 bytes (encrypted along with the content to preserve deniability)
- encrypted content = content.len()
- Poly1305 MAC = 16 bytes

## Security

*THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.*
