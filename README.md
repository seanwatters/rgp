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

// MAX content size: 74.840698 mb
let content = vec![0u8; 1214];

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

## Limits

- MAX public keys -> 65,535
- MAX content size -> 74.840698 mb

### Reasoning

IPv6 minimum MTU 1,280 bytes

each UDP packet in our system needs:
- IPv6 headers (40 bytes)
- UDP headers (8 bytes)
- uuid (16 bytes)
- position (2 bytes)

our base, usable packet size, is 1,214 bytes (1,280 bytes - 40 bytes - 8 bytes - 16 bytes - 2 bytes)

*total possible in a “payload” with a 16 bit position counter is 79.55949 mb (1,214 bytes * 65,535)*

Encryption Components:
- inner signature = 64 bytes
- one-time public key = 32 bytes
- Poly1305 MAC = 16 bytes
- nonce = 24 bytes
- keys count header = 2 bytes
- **MAX public keys (encrypted keys = 72 bytes * 65,535) = 4.71852 mb**

*remaining "payload" space is 74.840832 mb*

Destination Components:
- location = 16 bytes
- PUT key = 16 bytes
- TTL
    - unit = 1 byte
    - duration = 1 byte

*remaining "payload" space is 74.840798 mb*

Server Authentication Components:
- payload signature = 64 bytes
- token
    - HMAC = 32 bytes
    - id = 16 bytes
    - exp = 8 bytes
    - verifying key = 32 bytes
    - capacity units = 1 byte
    - write ops per CU = 2 bytes
    - write bytes per CU = 4 bytes
    - TTL cost multiplier
        - hour = 1 byte
        - day = 1 byte
        - month = 1 byte
        - year = 1 byte
        - infinite = 1 byte

**MAX content size is 74.840698 mb**

## Security

*THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.*
