# RGP

[![ci](https://github.com//seanwatters/RGP/actions/workflows/ci.yml/badge.svg)](https://github.com//seanwatters/RGP/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/seanwatters/RGP.svg)](https://github.com/seanwatters/RGP/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/seanwatters/RGP/status.svg)](https://deps.rs/repo/github/seanwatters/RGP)

Relatively Good Privacy 

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

### Disable Multi-threading

The `"multi-thread"` feature is enabled by default and utilizes the [Rayon](https://crates.io/crates/rayon) crate. It only impacts the `content::encrypt` function, but can be disabled by setting `default-features` to `false`.

```toml
# Cargo.toml

[dependencies]
rgp = { version = "x.x.x", default-features = false }
```

## Process

1. Generate one-time and ephemeral components
    - **nonce**
    - **one-time content key**
    - **ephemeral private key**
    - **one-time public key**
2. Sign plaintext to generate **content signature**
3. Encrypt plaintext and **content signature** with **one-time content key**
4. Encrypt **one-time content key** for all recipients
    - Generate **shared secret** with **recipient public key** and **ephemeral private key**
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
| encrypt (multi-thread)  | 97.186 ms |
| encrypt (single-thread) | 764.00 ms |
| extract                 | 486.00 µs |
| decrypt                 | 44.729 ms |

Doing the equivalent operation for just 1 recipient on 8mb is

| Operation               | Time      |
| ----------------------- | --------- |
| encrypt (multi-thread)  | 61.212 ms |
| encrypt (single-thread) | 61.314 ms |
| decrypt                 | 44.729 ms |

When benchmarked in isolation, the signing operation (internal to the `encrypt` function) and verifying operation (internal to the `decrypt` function), take 28.469 ms and 14.209 ms, respectively.

To check performance on your machine, run `cargo bench` (or `cargo bench --no-default-features` to disable multi-threading). You can also view the latest benches in the GitHub CI [workflow](https://github.com//seanwatters/RGP/actions/workflows/ci.yml) under job/Benchmark or job/Benchmark (single threaded).

**NOTE:** in multi-threaded mode the content signing/encryption logic is done in a separate thread from the per-recipient **content key** encryption, and the **content key** encryption work is done in a Rayon `par_chunks_mut` for loop. There is likely an opportunity for further parallelization in the content encryption and signing step.

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
