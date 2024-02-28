/*
RGP was built to enable E2EE for a broad range of applications

Copyright (C) 2024  Ordinary Labs, LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use std::fs::{remove_file, File, OpenOptions};
use std::io::Write;

use rgp::{
    decrypt, encrypt, extract_components_mut, generate_dh_keys, generate_fingerprint,
    generate_kem_keys, Components, Decrypt, Encrypt, KemKeyReader,
};

fn session_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    c.bench_function("session_encrypt", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Session(key, false)),
            )
            .unwrap();
        })
    });
}

fn hmac_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (hmac_key, key) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    c.bench_function("hmac_encrypt", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Hmac(hmac_key, key, 0)),
            )
            .unwrap();
        })
    });
}

fn dh_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();

    let (sender_priv_key, _) = generate_dh_keys();
    let (_, receiver_pub_key) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];
    let pub_keys = vec![receiver_pub_key];

    c.bench_function("dh_encrypt", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Dh(sender_priv_key, &pub_keys, None)),
            )
            .unwrap();
        })
    });
}

fn dh_encrypt_multi_recipient_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (sender_priv_key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];
    let mut pub_keys = vec![];

    for _ in 0..10_000 {
        let (_, pub_key) = generate_dh_keys();
        pub_keys.push(pub_key)
    }

    c.bench_function("dh_encrypt_multi_recipient", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Dh(sender_priv_key, &pub_keys, None)),
            )
            .unwrap();
        })
    });
}

fn kem_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();

    let (_, recipient_pub_key) = generate_kem_keys();

    let mut pub_keys_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("bench_pub_keys")
        .unwrap();

    pub_keys_file.write_all(&recipient_pub_key).unwrap();
    pub_keys_file.flush().unwrap();

    let content = vec![0u8; 5_000_000];

    c.bench_function("kem_encrypt", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Kem(KemKeyReader::new(
                    File::open("bench_pub_keys").unwrap(),
                ))),
            )
            .unwrap();
        })
    });

    remove_file("bench_pub_keys").unwrap();
}

fn kem_encrypt_multi_recipient_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();

    let (_, recipient_pub_key) = generate_kem_keys();

    let mut pub_keys_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("bench_pub_keys")
        .unwrap();

    for _ in 0..10_000 {
        pub_keys_file.write_all(&recipient_pub_key).unwrap();
        pub_keys_file.flush().unwrap();
    }

    let content = vec![0u8; 5_000_000];

    c.bench_function("kem_encrypt_multi_recipient", |b| {
        b.iter(|| {
            encrypt(
                black_box(fingerprint),
                black_box(content.clone()),
                black_box(Encrypt::Kem(KemKeyReader::new(
                    File::open("bench_pub_keys").unwrap(),
                ))),
            )
            .unwrap();
        })
    });

    remove_file("bench_pub_keys").unwrap();
}

fn session_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = generate_fingerprint();
    let (session_key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    let (mut encrypted_content, _) =
        encrypt(fingerprint, content, Encrypt::Session(session_key, false)).unwrap();

    extract_components_mut(0, &mut encrypted_content);

    c.bench_function("session_decrypt", |b| {
        b.iter(|| {
            decrypt(
                black_box(Some(&verifying_key)),
                black_box(&encrypted_content),
                black_box(Decrypt::Session(session_key, None)),
            )
            .unwrap();
        })
    });
}

fn hmac_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = generate_fingerprint();
    let (hmac_key, hmac_value) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    let (mut encrypted_content, _) =
        encrypt(fingerprint, content, Encrypt::Hmac(hmac_key, hmac_value, 0)).unwrap();

    extract_components_mut(0, &mut encrypted_content);

    c.bench_function("hmac_decrypt", |b| {
        b.iter(|| {
            decrypt(
                black_box(Some(&verifying_key)),
                black_box(&encrypted_content),
                black_box(Decrypt::Hmac(hmac_key, hmac_value)),
            )
            .unwrap();
        })
    });
}

fn dh_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = generate_fingerprint();
    let (sender_priv_key, sender_pub_key) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];
    let (receiver_priv_key, receiver_pub_key) = generate_dh_keys();

    let pub_keys = vec![receiver_pub_key];

    let (mut encrypted_content, _) = encrypt(
        fingerprint,
        content,
        Encrypt::Dh(sender_priv_key, &pub_keys, None),
    )
    .unwrap();

    let content_key = match extract_components_mut(0, &mut encrypted_content) {
        Components::Dh(key, _) => key,
        _ => unreachable!(),
    };

    c.bench_function("dh_decrypt", |b| {
        b.iter(|| {
            decrypt(
                black_box(Some(&verifying_key)),
                black_box(&encrypted_content),
                black_box(Decrypt::Dh(
                    content_key,
                    sender_pub_key,
                    receiver_priv_key,
                    None,
                )),
            )
            .unwrap();
        })
    });
}

fn kem_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifier) = generate_fingerprint();

    let (recipient_secret_key, recipient_pub_key) = generate_kem_keys();

    let mut pub_keys_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("bench_pub_keys")
        .unwrap();

    pub_keys_file.write_all(&recipient_pub_key).unwrap();
    pub_keys_file.flush().unwrap();

    let content = vec![0u8; 5_000_000];

    let (mut encrypted_content, _) = encrypt(
        fingerprint,
        content.clone(),
        Encrypt::Kem(KemKeyReader::new(File::open("bench_pub_keys").unwrap())),
    )
    .unwrap();

    let (encrypted_key, ciphertext) = match extract_components_mut(0, &mut encrypted_content) {
        Components::Kem(encrypted_key, ciphertext, _) => (encrypted_key, ciphertext),
        _ => unreachable!(),
    };

    c.bench_function("kem_decrypt", |b| {
        b.iter(|| {
            decrypt(
                black_box(Some(&verifier)),
                black_box(&encrypted_content),
                black_box(Decrypt::Kem(
                    encrypted_key,
                    ciphertext,
                    recipient_secret_key,
                    None,
                )),
            )
            .unwrap();
        })
    });

    remove_file("bench_pub_keys").unwrap();
}

criterion_group!(
    benches,
    session_encrypt_benchmark,
    hmac_encrypt_benchmark,
    dh_encrypt_benchmark,
    dh_encrypt_multi_recipient_benchmark,
    kem_encrypt_benchmark,
    kem_encrypt_multi_recipient_benchmark,
    session_decrypt_benchmark,
    hmac_decrypt_benchmark,
    dh_decrypt_benchmark,
    kem_decrypt_benchmark,
);

criterion_main!(benches);
