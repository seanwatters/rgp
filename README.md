# RGP

[![ci](https://github.com//seanwatters/rgp/actions/workflows/ci.yml/badge.svg)](https://github.com//seanwatters/rgp/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/seanwatters/rgp.svg)](https://github.com/seanwatters/rgp/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/seanwatters/rgp/status.svg)](https://deps.rs/repo/github/seanwatters/rgp)

Relatively Good Privacy 

## Usage

```rust
let (fingerprint, verifying_key) = rgp::generate_fingerprint();

let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();
let (first_recipient_priv_key, first_recipient_pub_key) = rgp::generate_dh_keys();

let mut pub_keys = vec![first_recipient_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// add another 20,000 recipients
for _ in 0..20_000 {
    let (_, pub_key) = rgp::generate_dh_keys();
    pub_keys.push(pub_key)
}

let (mut encrypted_content, _) = rgp::encrypt(
    fingerprint,
    content.clone(),
    rgp::Mode::Dh(sender_priv_key, &pub_keys),
)
.unwrap();

// extract for first recipient
rgp::extract_for_key_position_mut(0, &mut encrypted_content).unwrap();

let decrypted_content = rgp::decrypt(
    Some(&verifying_key),
    sender_pub_key,
    first_recipient_priv_key,
    &encrypted_content,
)
.unwrap();

assert_eq!(decrypted_content, content);
```

## Modes

There are currently 3 supported modes: `Dh` (Diffie-Hellman), `Hash`, and `Session`.

### Diffie-Hellman

Diffie-Hellman mode is the most resilient to break-ins as it generates a fresh/random **content key**, and encrypts it with a **shared secret** for each intended recipient for each message. It is also currently the option with the highest overhead for both computation and storage, as it inflates the encrypted content payload by 32 bytes for each recipient, and also requires the computation of the **shared secret** / encryption of the **content key** with said **shared secret** on a per-recipient basis.

`Dh` mode should always be used to bootstrap an interaction even if `Hash` and/or `Session` modes are sufficiently secure for the use case, post key exchange.

Process:

1. Generate one-time components
    - **nonce**
    - **content key**
2. Sign plaintext to generate **content signature**
3. Encrypt plaintext and **content signature** with _one-time_ **content key**
4. Encrypt _one-time_ **content key** for all recipients
    - Generate **shared secret** with **recipient public key** and **sender private key**
    - Encrypt _one-time_ **content key** with **shared secret**

### Hash

Hash mode, while it doesn't provide the same level of security as random key generation/per-recipient key encryption, it does enable backward secrecy, and when used with a non-constant hash key/value, it can protect forward secrecy when only the **content key** is compromised.

Process:

1. Generate **nonce**
2. Hash the content key
3. Sign plaintext to generate **content signature**
4. Encrypt plaintext and **content signature** with the _hashed_ **content key**

### Session

This mode provides no forward or backward secrecy, and uses the provided key "as is" without any modification. This is essentially the same as just running the underlying symmetric cipher.

Process:

1. Generate **nonce**
2. Sign plaintext to generate **content signature**
3. Encrypt plaintext and **content signature** with the provided **content key**, as is

## Ciphersuite

- Blake2s256 for **content key** hashing
- Ed25519 for **signatures**
- XChaCha20Poly1305 for content
- X25519 for Diffie-Hellman **shared secret** generation
- XChaCha20 for _one-time_ **content key** encryption

## Encrypted Format

- **nonce** = 24 bytes
- mode = 1 byte (0 for `Session` | 1 for `Hash` | 2 for `Dh`)
- keys count (`Dh` mode only)
    - int size = 2 bits
    - count
        - numbers 0-63 = 6 bits
        - numbers >63 = 1-8 bytes (big endian int)
- encrypted copies of **content key** (`Dh` mode only) = pub_keys.len() * 32 bytes
- encrypted content = content.len()
- **signature** = 64 bytes (encrypted along with the content to preserve deniability)
- Poly1305 MAC = 16 bytes

## Performance

To check performance on your machine, run `cargo bench`. You can also view the latest benches in the GitHub CI [workflow](https://github.com//seanwatters/rgp/actions/workflows/ci.yml) under job/Benchmark.

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.
