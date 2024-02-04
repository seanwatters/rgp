# Ordinal Crypto 🔐

![ci](https://github.com//ordinarylabs/ordinal-crypto/actions/workflows/rust.yml/badge.svg)
[![crates.io](https://img.shields.io/crates/v/ordinal_crypto.svg)](https://crates.io/crates/ordinal_crypto)
[![docs.rs](https://docs.rs/ordinal_crypto/badge.svg)](https://docs.rs/ordinal_crypto/)
[![license](https://img.shields.io/github/license/ordinarylabs/ordinal-crypto.svg)](https://github.com/ordinarylabs/ordinal-crypto/blob/main/LICENSE)
[![dependency status](https://deps.rs/repo/github/ordinarylabs/ordinal-crypto/status.svg)](https://deps.rs/repo/github/ordinarylabs/ordinal-crypto)

The cryptography library for the Ordinal Platform

## Usage

```rust
let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();

let content = vec![0u8; 1215];

// MAX pub keys: 65,535
let pub_keys = vec![pub_key];

let encrypted_content =
    ordinal_crypto::content::encrypt(&fingerprint, &content, pub_keys).unwrap();

let (encrypted_content, encrypted_key) =
    ordinal_crypto::content::extract_components_for_key_position(&encrypted_content, 0)
        .unwrap();

let decrypted_content = ordinal_crypto::content::decrypt(
    Some(&verifying_key),
    priv_key,
    &encrypted_key,
    &encrypted_content,
)
.unwrap();

assert_eq!(decrypted_content, content);
```

## Format

- keys count header = 2 bytes
- encrypted keys = 72 bytes (max is 65,535 or 4.71852 mb)
- one-time public key = 32 bytes
- nonce = 24 bytes
- inner signature = 64 bytes (encrypted along with the content to preserve deniability)
- Poly1305 MAC = 16 bytes

## Security

*THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.*
