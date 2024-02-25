# RGP

[![ci](https://github.com//seanwatters/rgp/actions/workflows/ci.yml/badge.svg)](https://github.com//seanwatters/rgp/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/seanwatters/rgp.svg)](https://github.com/seanwatters/rgp/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/seanwatters/rgp/status.svg)](https://deps.rs/repo/github/seanwatters/rgp)

Relatively Good Privacy

## Modes

There are currently three supported modes: `Dh` (Diffie-Hellman), `Hmac`, and `Session`. All modes provide the ability to sign content and verify the sender. Deniability is preserved by signing the plaintext and encrypting the signature alongside the plaintext.

### Diffie-Hellman

`Dh` mode provides forward secrecy by generating a fresh/random content key for each message and encrypting a copy of that key for each recipient (similar to PGP session keys).

This mode can also be used to bootstrap the initial key exchange for `Session` and `Hmac` modes.

```rust
// TODO
```

#### Steps

1. Generate one-time components
    - nonce
    - content key
2. Sign plaintext to generate content signature
3. Encrypt plaintext and content signature with content key
4. Encrypt content key for all recipients
    - Generate shared secret with recipient's public key and sender's private key
    - Encrypt content key with shared secret

#### Format

- nonce = 24 bytes
- keys count
    IF 0..=127
        - is single byte = 1 bit (set)
        - count = 7 bits
    ELSE
        - is single byte = 1 bit (unset)
        - int size = 2 bits
        - count = 8-64 bits
- encrypted copies of content key = pub_keys.len() * 32 bytes
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 2 for `Dh`)

### HMAC

`Hmac` mode provides backward secrecy, and can enable forward secrecy when the HMAC key is kept secret, if only the content key is compromised. Includes an iterator to make "ratcheting" logic easier to implement.

```rust
// TODO
```

#### Steps

1. Generate nonce
2. Hash the provided components
3. Sign plaintext to generate content signature
4. Encrypt plaintext and content signature with the hashed key

#### Format

- nonce = 24 bytes
- iteration
    - int size = 2 bits
    - iteration
        - numbers 0-63 = 6 bits
        - numbers >63 = 1-8 bytes (big endian int)
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 1 for `Hmac`)

### Session

`Session` provides no forward or backward secrecy, and uses the provided key "as is" without any modification.

```rust
// TODO
```

#### Steps

1. Generate nonce
2. Sign plaintext to generate content signature
3. Encrypt plaintext and content signature with the provided key

#### Format

- nonce = 24 bytes
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 0 for `Session`)

## Ciphersuite

- Blake2s256 for hashing
- Ed25519 for signatures
- X25519 for shared secrets
- XChaCha20 for content keys
- XChaCha20Poly1305 for content

## Disable Multi-threading

The `"multi-thread"` feature is enabled by default and utilizes the [Rayon](https://crates.io/crates/rayon) crate. Currently it only impacts the `encrypt` function when using `Dh` mode, but can be disabled by setting `default-features` to `false`.

```toml
[dependencies]
rgp = { version = "x.x.x", default-features = false }
```

## Performance

To check performance on your machine, run `cargo bench`. You can also view the latest benches in the GitHub CI [workflow](https://github.com//seanwatters/rgp/actions/workflows/ci.yml).

All benchmarks for multi-recipient `Dh` payloads are for **10,000** recipients, and all benchmarks for sign+encrypt/decrypt+verify are using **5mb** of data.

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

