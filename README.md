# RGP

[![ci](https://github.com//ordinarylabs/RGP/actions/workflows/ci.yml/badge.svg)](https://github.com//ordinarylabs/RGP/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![license](https://img.shields.io/github/license/ordinarylabs/RGP.svg)](https://github.com/ordinarylabs/RGP/blob/main/LICENSE)
[![dependency status](https://deps.rs/repo/github/ordinarylabs/RGP/status.svg)](https://deps.rs/repo/github/ordinarylabs/RGP)

Reasonably Good Privacy

## Usage

```rust
let (our_priv_key, our_pub_key) = rgp::generate_exchange_keys();
let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();

let mut pub_keys = vec![our_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// 20,000 recipients
for _ in 0..20_000 {
    let (_, pub_key) = rgp::generate_exchange_keys();
    pub_keys.push(pub_key)
}

let mut encrypted_content =
    rgp::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();

let encrypted_content =
    rgp::content::extract_content_for_key_position(&mut encrypted_content, 0)
        .unwrap();

let decrypted_content = rgp::content::decrypt(
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
- keys count (2-9 bytes)
    - int size = 1 byte (1 for u8 | 2 for u16 | 4 for u32 | 8 for u64)
    - big endian int = 1-8 bytes
- encrypted keys = pub_keys.len() * 32 bytes
- inner signature = 64 bytes (encrypted along with the content to preserve deniability)
- encrypted content = content.len()
- Poly1305 MAC = 16 bytes

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.
