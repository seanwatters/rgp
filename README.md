# RGP

[![ci](https://github.com//seanwatters/rgp/actions/workflows/ci.yml/badge.svg)](https://github.com//seanwatters/rgp/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/seanwatters/rgp.svg)](https://github.com/seanwatters/rgp/blob/main/LICENSE)
[![crates.io](https://img.shields.io/crates/v/rgp.svg)](https://crates.io/crates/rgp)
[![docs.rs](https://docs.rs/rgp/badge.svg)](https://docs.rs/rgp/)
[![dependency status](https://deps.rs/repo/github/seanwatters/rgp/status.svg)](https://deps.rs/repo/github/seanwatters/rgp)

_"Relatively Good Privacy"_

## Usage

```rust
use rgp::{
    decrypt, encrypt, extract_components_mut, generate_dh_keys,
    generate_fingerprint, Components, Decrypt, Encrypt
};

// generate sender fingerprint and public verifier
let (fingerprint, verifier) = generate_fingerprint();

// generate key pairs for sender and recipient
let (sender_priv_key, sender_pub_key) = generate_dh_keys();
let (recipient_priv_key, recipient_pub_key) = generate_dh_keys();

let mut pub_keys = vec![recipient_pub_key];

// 8mb
let content = vec![0u8; 8_000_000];

// add another 20,000 recipients
for _ in 0..20_000 {
    let (_, pub_key) = generate_dh_keys();
    pub_keys.push(pub_key)
}

// encrypt message for all recipients
let (mut encrypted_content, content_key) = encrypt(
    fingerprint,
    content.clone(),
    Encrypt::Dh(sender_priv_key, &pub_keys, None),
)
.unwrap();

// extract encrypted content key for first recipient
if let Components::Dh(encrypted_key, _) = 
    extract_components_mut(0, &mut encrypted_content) 
{
    // decrypt message
    let (decrypted_content, decrypted_content_key) = decrypt(
        Some(&verifier),
        &encrypted_content,
        Decrypt::Dh(
            encrypted_key, 
            sender_pub_key, 
            recipient_priv_key, 
            None,
        ),
    )
    .unwrap();
    
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_content_key, content_key);
};
```

More in the [examples](https://github.com/seanwatters/rgp/tree/main/examples) directory.

## Modes

There are currently 4 supported top-level modes: `Dh` (Diffie-Hellman), `Hmac`, `Session` and `Kem` (Key Encapsulation Mechanism). All modes embed content signing and verification; deniability is preserved by signing the plaintext and encrypting the signature alongside the plaintext.

#### Ciphersuite

- Blake2s256 for HMAC
- Ed25519 for signatures
- mceliece348864 for KEM
- X25519 for Diffie-Hellman
- XChaCha20 for content keys
- XChaCha20Poly1305 for content

### Diffie-Hellman

`Dh` mode provides forward secrecy by generating a fresh/random content key for each message and encrypting a copy of that key for each recipient with their respective shared secrets (similar to PGP session keys). This mode can be used to manage the initial key exchange/ratchet seeding for `Session` and `Hmac` modes.

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
    - int size = 2 bits
    - count
        - numbers 0-63 = 6 bits
        - numbers >63 = 1-8 bytes (big endian int)
- encrypted copies of content key = pub_keys.len() * 32 bytes
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 2 for `Dh` or 4 for `Dh` with HMAC)

### HMAC

`Hmac` mode provides backward secrecy, and can enable forward secrecy when the HMAC key is kept secret, if only the content key is compromised. Includes an iterator to make ratcheting logic easier to implement.

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

`Session` by default provides no forward or backward secrecy, and uses the provided key "as is" without any modification. `Session` with key gen, however, does provide a weak forward secrecy as it will generate a fresh/single-use content key that is itself encrypted with the session key, thus protecting the session key if only the content key is compromised.

#### Steps

1. Generate one-time components
    - nonce
    - content key (`Session` with key gen only)
2. Sign plaintext to generate content signature
3. Encrypt plaintext and content signature with the content or session key
4. Encrypt content key with session key (`Session` with key gen only)

#### Format

- nonce = 24 bytes
- encrypted key = 32 bytes (`Session` with key gen only)
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 0 for `Session` or 3 for `Session` with key gen)

### KEM

`Kem` mode is designed to facilitate public key cryptography for post-quantum encryption. It enables forward secrecy by generating a fresh/random content key for each message and encrypting a copy of that key for each recipient with their respective encapsulated keys.

This mode can be used to manage the initial key exchange/ratchet seeding for `Session` and `Hmac` as well as seed an HMAC key for usage with `Dh` mode.

This mode depends on the [classic-mceliece-rust](https://crates.io/crates/classic-mceliece-rust) crate. It is recommended that the `Kem` with Diffie-Hellman hybrid, option be used until the underlying PQ crypto has been sufficiently validated.

Classic McEliece was chosen despite its larger key sizes because it has a much smaller ciphertext, which is included for each recipient on each message. Given that for this mode the size of the actual output is only increased by 96 bytes per-recipient (as compared to `Dh` mode), it is possible that `Kem` could be optimized to read from a stream of public keys so that they don't all have to fit in memory at one time, but for now this "smaller batches" limitation feels reasonable as the encapsulate/decapsulate operations also come with a fairly high computational overhead.

#### Steps

1. Generate one-time components
    - nonce
    - content key
2. Sign plaintext to generate content signature
3. Encrypt plaintext and content signature with content key
4. Encrypt content key for all recipients
    - Generate ciphertext and encapsulated key with recipient's public key and sender's private key
    - Encrypt content key with encapsulated key
    - Append ciphertext to encrypted content key

#### Format

- nonce = 24 bytes
- keys count
    - int size = 2 bits
    - count
        - numbers 0-63 = 6 bits
        - numbers >63 = 1-8 bytes (big endian int)
- encrypted copies of content key + ciphertext = pub_keys.len() * (32 bytes + 96 bytes)
- encrypted content = content.len()
- signature = 64 bytes (encrypted along with the content)
- Poly1305 MAC = 16 bytes
- mode = 1 byte (set to 5 for `Kem` or 6 for `Kem` with Diffie-Hellman)

## Performance

To check performance on your machine, run `cargo bench`. You can also view the latest benches in the GitHub CI [workflow](https://github.com//seanwatters/rgp/actions/workflows/ci.yml).

All benchmarks for multi-recipient `Dh` payloads are for **10,000** recipients, and all benchmarks for sign+encrypt/decrypt+verify are using **5mb** of data.

## Disable Multi-threading

The `"multi-thread"` feature is enabled by default and utilizes the [Rayon](https://crates.io/crates/rayon) crate. Multi-threading is currently only used in the `encrypt` function when using `Dh` or `Kem` modes to encrypt keys and content in parallel, but can be disabled by setting `default-features` to `false`.

```toml
[dependencies]
rgp = { version = "x.x.x", default-features = false }
```

## License

[MIT](https://opensource.org/license/MIT)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

