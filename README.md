# RGP

[![ci](https://github.com//seanwatters/rgp/actions/workflows/ci.yml/badge.svg)](https://github.com//seanwatters/rgp/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/seanwatters/rgp.svg)](https://github.com/seanwatters/rgp/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/seanwatters/rgp/status.svg)](https://deps.rs/repo/github/seanwatters/rgp)

Relatively Good Privacy 

## Usage

```rust
let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();

let (sender_priv_key, sender_pub_key) = rgp::generate_exchange_keys();
let (first_recipient_priv_key, first_recipient_pub_key) = rgp::generate_exchange_keys();

let mut pub_keys = vec![first_recipient_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// add another 20,000 recipients
for _ in 0..20_000 {
    let (_, pub_key) = rgp::generate_exchange_keys();
    pub_keys.push(pub_key)
}

let mut encrypted_content = rgp::content::encrypt(
    fingerprint,
    content.clone(),
    sender_priv_key,
    &pub_keys,
)
.unwrap();

// extract for first recipient
rgp::content::extract_content_for_key_position(
    &mut encrypted_content,
    0
)
.unwrap();

let decrypted_content = rgp::content::decrypt(
    Some(&verifying_key),
    sender_pub_key,
    first_recipient_priv_key,
    &encrypted_content,
)
.unwrap();

assert_eq!(decrypted_content, content);
```

### Disable Multi-threading

The `"multi-thread"` feature is enabled by default and utilizes the [Rayon](https://crates.io/crates/rayon) crate. It only impacts the `content::encrypt` function, but can be disabled by setting `default-features` to `false`.

```toml
# Cargo.toml

[dependencies]
rgp = { version = "x.x.x", default-features = false }
```

## Process

1. Generate one-time components
    - **nonce**
    - **content key**
2. Sign plaintext to generate **content signature**
3. Encrypt plaintext and **content signature** with **one-time content key**
4. Encrypt **one-time content key** for all recipients
    - Generate **shared secret** with **recipient public key** and **sender private key**
    - Encrypt **one-time content key** with **shared secret**

## Ciphersuite

- Ed25519 for **signatures**
- XChaCha20Poly1305 for content
- X25519 for Diffie-Hellman **shared secret** generation
- XChaCha20 for **one-time content key** encryption

## Performance

For the 8mb example with 20,000 recipients, on my M1 MacBook Pro

| Operation               | Time      |
| ----------------------- | --------- |
| encrypt (multi-thread)  | 96.606 ms |
| encrypt (single-thread) | 758.99 ms |
| extract                 | 322.95 µs |
| decrypt                 | 44.399 ms |

Doing the equivalent operation for just 1 recipient on 8mb is

| Operation               | Time      |
| ----------------------- | --------- |
| encrypt (multi-thread)  | 60.714 ms |
| encrypt (single-thread) | 60.889 ms |

When benchmarked in isolation, the signing operation (internal to the `encrypt` function) and verifying operation (internal to the `decrypt` function), take 28.469 ms and 14.209 ms, respectively.

To check performance on your machine, run `cargo bench` (or `cargo bench --no-default-features` to disable multi-threading). You can also view the latest benches in the GitHub CI [workflow](https://github.com//seanwatters/rgp/actions/workflows/ci.yml) under job/Benchmark or job/Benchmark (single threaded).

**NOTE:** in multi-threaded mode the content signing/encryption logic is done in a separate thread from the per-recipient **content key** encryption, and the **content key** encryption work is done in a Rayon `par_chunks_mut` for loop. There is likely an opportunity for further parallelization in the content encryption and signing step.

## Encrypted Format

- **nonce** = 24 bytes
- keys count (1-9 bytes)
    - int size = 2 bits (0 for u8+63 | 1 for u16+63 | 2 for u32+63 | 3 for u64+63)
    - count
        - numbers 0-63 = 6 bits
        - numbers >63 = 1-8 bytes (big endian int)
- encrypted keys = pub_keys.len() * 32 bytes
- encrypted content = content.len()
- **signature** = 64 bytes (encrypted along with the content to preserve deniability)
- Poly1305 MAC = 16 bytes

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.
