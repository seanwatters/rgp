# RGP

[![ci](https://github.com/seanwatters/rgp/actions/workflows/ci.yml/badge.svg)](https://github.com/seanwatters/rgp/actions/workflows/ci.yml)
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

## Disable Multi-threading

The `"multi-thread"` feature is enabled by default and utilizes the [Rayon](https://crates.io/crates/rayon) crate. Multi-threading is currently only used in the `encrypt` function when using `Dh` or `Kem` modes to encrypt keys and content in parallel, but can be disabled by setting `default-features` to `false`.

```toml
[dependencies]
rgp = { version = "x.x.x", default-features = false }
```

## Modes

There are currently 4 supported top-level modes: `Dh` (Diffie-Hellman), `Hmac`, `Session` and `Kem` (Key Encapsulation Mechanism). All modes embed content signing and verification; deniability is preserved by signing the plaintext and encrypting the signature alongside the plaintext.

#### Ciphersuite

- Blake2s256 for HMAC
- Ed25519 for signatures
- mceliece348864f for KEM
- X25519 for Diffie-Hellman
- XChaCha20 for content keys
- XChaCha20Poly1305 for content

### Diffie-Hellman

`Dh` mode provides forward secrecy by generating a fresh/random content key for each message and encrypting a copy of that key for each recipient with their respective shared secrets (similar to PGP session keys). This mode can be used to manage the initial key exchange/ratchet seeding for `Session` and `Hmac` modes.

### HMAC

`Hmac` mode provides backward secrecy, and can enable forward secrecy when the HMAC key is kept secret, if only the content key is compromised. This mode also keeps track of an iterator to make ratcheting logic easier to implement.

### Session

`Session` by default provides no forward or backward secrecy, and uses the provided key "as is" without any modification. When used with keygen, `Session` can provide a forward secrecy for the content key as it will generate a fresh/single-use content key that is itself encrypted with the session key, thus protecting the session key if only the content key is compromised.

### KEM

`Kem` mode is designed to facilitate public key cryptography for post-quantum encryption. It enables forward secrecy by generating a fresh/random content key for each message and encrypting a copy of that key for each recipient with their respective encapsulated keys.

This mode can be used to manage the initial key exchange/ratchet seeding for `Session` and `Hmac` as well as seed an HMAC key for usage with `Dh` mode.

This mode depends on the [classic-mceliece-rust](https://crates.io/crates/classic-mceliece-rust) crate. It is recommended that the `Kem` with Diffie-Hellman hybrid, option be used until the underlying PQ crypto has been sufficiently validated.

Classic McEliece was chosen despite its larger key sizes because it has a much smaller ciphertext, which is included for each recipient on each message.

## Performance

To check performance on your machine, run `cargo bench`. You can also view the latest benches in the GitHub CI [workflow](https://github.com/seanwatters/rgp/actions/workflows/ci.yml).

All benchmarks for multi-recipient `Dh` and `Kem` mode are for **10,000** recipients, and all benchmarks for sign+encrypt/decrypt+verify are using **5mb** payloads.

## License

[MIT](https://github.com/seanwatters/rgp/blob/main/LICENSE)

## Security

THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.

