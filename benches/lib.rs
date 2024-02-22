/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use criterion::{criterion_group, criterion_main, Criterion};

fn generate_fingerprint_benchmark(c: &mut Criterion) {
    c.bench_function("generate_fingerprint", |b| {
        b.iter(|| {
            rgp::generate_fingerprint();
        })
    });
}

fn sign_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let content = [0u8; 8_000_000];

    c.bench_function("sign", |b| {
        b.iter(|| {
            rgp::sign(&fingerprint, &content);
        })
    });
}

fn verify_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::generate_fingerprint();
    let content = [0u8; 8_000_000];

    let signature = rgp::sign(&fingerprint, &content);

    c.bench_function("verify", |b| {
        b.iter(|| {
            rgp::verify(&signature, &verifying_key, &content).unwrap();
        })
    });
}

fn generate_dh_keys_benchmark(c: &mut Criterion) {
    c.bench_function("generate_dh_keys", |b| {
        b.iter(|| {
            rgp::generate_dh_keys();
        })
    });
}

fn session_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let (key, _) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];

    c.bench_function("session_encrypt", |b| {
        b.iter(|| {
            rgp::encrypt(fingerprint, content.clone(), rgp::EncryptMode::Session(key)).unwrap();
        })
    });
}

fn hash_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let (hash_key, key) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];

    c.bench_function("hash_encrypt", |b| {
        b.iter(|| {
            rgp::encrypt(
                fingerprint,
                content.clone(),
                rgp::EncryptMode::Hmac(hash_key, key, 0),
            )
            .unwrap();
        })
    });
}

fn dh_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();

    let (sender_priv_key, _) = rgp::generate_dh_keys();
    let (_, receiver_pub_key) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];
    let pub_keys = vec![receiver_pub_key];

    c.bench_function("dh_encrypt", |b| {
        b.iter(|| {
            rgp::encrypt(
                fingerprint,
                content.clone(),
                rgp::EncryptMode::Dh(sender_priv_key, &pub_keys),
            )
            .unwrap();
        })
    });
}

fn dh_encrypt_multi_recipient_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let (sender_priv_key, _) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = rgp::generate_dh_keys();
        pub_keys.push(pub_key)
    }

    c.bench_function("dh_encrypt_multi_recipient", |b| {
        b.iter(|| {
            rgp::encrypt(
                fingerprint,
                content.clone(),
                rgp::EncryptMode::Dh(sender_priv_key, &pub_keys),
            )
            .unwrap();
        })
    });
}

fn extract_mode_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let (sender_priv_key, _) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = rgp::generate_dh_keys();
        pub_keys.push(pub_key)
    }

    let (encrypted_content, _) = rgp::encrypt(
        fingerprint,
        content,
        rgp::EncryptMode::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    c.bench_function("extract_mode", |b| {
        b.iter(|| {
            rgp::extract_mode(0, encrypted_content.clone());
        })
    });
}

fn extract_mode_mut_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::generate_fingerprint();
    let (sender_priv_key, _) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = rgp::generate_dh_keys();
        pub_keys.push(pub_key)
    }

    let (encrypted_content, _) = rgp::encrypt(
        fingerprint,
        content,
        rgp::EncryptMode::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    c.bench_function("extract_mode_mut", |b| {
        b.iter(|| {
            rgp::extract_mode_mut(0, &mut encrypted_content.clone());
        })
    });
}

fn session_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::generate_fingerprint();
    let (key, _) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];

    let (mut encrypted_content, _) =
        rgp::encrypt(fingerprint, content, rgp::EncryptMode::Session(key)).unwrap();

    rgp::extract_mode_mut(0, &mut encrypted_content);

    c.bench_function("session_decrypt", |b| {
        b.iter(|| {
            rgp::decrypt(
                Some(&verifying_key),
                &encrypted_content,
                rgp::DecryptMode::Session(key),
            )
            .unwrap();
        })
    });
}

fn hash_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::generate_fingerprint();
    let (hash_key, key) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];

    let (mut encrypted_content, _) = rgp::encrypt(
        fingerprint,
        content,
        rgp::EncryptMode::Hmac(hash_key, key, 0),
    )
    .unwrap();

    rgp::extract_mode_mut(0, &mut encrypted_content);

    c.bench_function("hash_decrypt", |b| {
        b.iter(|| {
            rgp::decrypt(
                Some(&verifying_key),
                &encrypted_content,
                rgp::DecryptMode::Hmac(hash_key, key),
            )
            .unwrap();
        })
    });
}

fn dh_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::generate_fingerprint();
    let (sender_priv_key, sender_pub_key) = rgp::generate_dh_keys();

    let content = vec![0u8; 8_000_000];
    let (receiver_priv_key, receiver_pub_key) = rgp::generate_dh_keys();

    let pub_keys = vec![receiver_pub_key];

    let (mut encrypted_content, _) = rgp::encrypt(
        fingerprint,
        content,
        rgp::EncryptMode::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    let content_key = match rgp::extract_mode_mut(0, &mut encrypted_content) {
        rgp::Mode::Dh(key) => key,
        _ => unreachable!(),
    };

    c.bench_function("dh_decrypt", |b| {
        b.iter(|| {
            rgp::decrypt(
                Some(&verifying_key),
                &encrypted_content,
                rgp::DecryptMode::Dh(content_key, sender_pub_key, receiver_priv_key),
            )
            .unwrap();
        })
    });
}

criterion_group!(
    benches,
    generate_fingerprint_benchmark,
    sign_benchmark,
    verify_benchmark,
    generate_dh_keys_benchmark,
    session_encrypt_benchmark,
    hash_encrypt_benchmark,
    dh_encrypt_benchmark,
    dh_encrypt_multi_recipient_benchmark,
    extract_mode_benchmark,
    extract_mode_mut_benchmark,
    session_decrypt_benchmark,
    hash_decrypt_benchmark,
    dh_decrypt_benchmark,
);

criterion_main!(benches);
