# RGP

[![ci](https://github.com//ordinarylabs/RGP/actions/workflows/ci.yml/badge.svg)](https://github.com//ordinarylabs/RGP/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/ordinarylabs/RGP.svg)](https://github.com/ordinarylabs/RGP/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/ordinarylabs/RGP/status.svg)](https://deps.rs/repo/github/ordinarylabs/RGP)

"Reasonably Good Privacy"

## Usage

```rust
let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();

let (our_priv_key, our_pub_key) = rgp::generate_exchange_keys();
let mut pub_keys = vec![our_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// 20,000 recipients
for _ in 0..20_000 {
    let (_, pub_key) = rgp::generate_exchange_keys();
    pub_keys.push(pub_key)
}

let mut encrypted_content = rgp::content::encrypt(
    fingerprint,
    content.clone(),
    &pub_keys
)
.unwrap();

rgp::content::extract_content_for_key_position(
    &mut encrypted_content,
    0
)
.unwrap();

let decrypted_content = rgp::content::decrypt(
    Some(&verifying_key),
    our_priv_key,
    &encrypted_content,
)
.unwrap();

assert_eq!(decrypted_content, content);
```

## Process

1. Generate one-time and ephemeral components
    - **one-time public key**
    - **ephemeral private key**
    - **nonce**
    - **one-time content key**
2. Sign plaintext to generate **content signature**
3. Encrypt plaintext and **content signature** with **one-time content key**
4. Encrypt **one-time content key** for all recipients
    - Generate **shared secret** with **recipient public key** and **ephemeral private key**
    - Encrypt **one-time content key** with **shared secret**

## Ciphersuite

- ChaCha20Poly1305 for content
- ChaCha20 for **one-time content key** encryption
- x25519 for Diffie-Hellman **shared secret** generation
- Ed25519 for **signatures**

## Encrypted Format

- **nonce** = 24 bytes
- **one-time public key** = 32 bytes
- keys count (2-9 bytes)
    - int size = 1 byte (1 for u8 | 2 for u16 | 4 for u32 | 8 for u64)
    - big endian int = 1-8 bytes
- encrypted keys = pub_keys.len() * 32 bytes
- encrypted content = content.len()
- **signature** = 64 bytes (encrypted along with the content to preserve deniability)
- Poly1305 MAC = 16 bytes

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.
