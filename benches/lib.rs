/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use criterion::{criterion_group, criterion_main, Criterion};

use rgp::{
    decrypt, encrypt, extract_components, extract_components_mut, generate_dh_keys,
    generate_fingerprint, Components, Decrypt, Encrypt,
};

fn session_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    c.bench_function("session_encrypt", |b| {
        b.iter(|| {
            encrypt(fingerprint, content.clone(), Encrypt::Session(key)).unwrap();
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
                fingerprint,
                content.clone(),
                Encrypt::Hmac(hmac_key, key, 0),
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
                fingerprint,
                content.clone(),
                Encrypt::Dh(sender_priv_key, &pub_keys),
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

    for _ in 0..20_000 {
        let (_, pub_key) = generate_dh_keys();
        pub_keys.push(pub_key)
    }

    c.bench_function("dh_encrypt_multi_recipient", |b| {
        b.iter(|| {
            encrypt(
                fingerprint,
                content.clone(),
                Encrypt::Dh(sender_priv_key, &pub_keys),
            )
            .unwrap();
        })
    });
}

fn extract_components_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (sender_priv_key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = generate_dh_keys();
        pub_keys.push(pub_key)
    }

    let (encrypted_content, _) = encrypt(
        fingerprint,
        content,
        Encrypt::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    c.bench_function("extract_components", |b| {
        b.iter(|| {
            extract_components(0, encrypted_content.clone());
        })
    });
}

fn extract_components_mut_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = generate_fingerprint();
    let (sender_priv_key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = generate_dh_keys();
        pub_keys.push(pub_key)
    }

    let (encrypted_content, _) = encrypt(
        fingerprint,
        content,
        Encrypt::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    c.bench_function("extract_components_mut", |b| {
        b.iter(|| {
            extract_components_mut(0, &mut encrypted_content.clone());
        })
    });
}

fn session_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = generate_fingerprint();
    let (key, _) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    let (mut encrypted_content, _) = encrypt(fingerprint, content, Encrypt::Session(key)).unwrap();

    extract_components_mut(0, &mut encrypted_content);

    c.bench_function("session_decrypt", |b| {
        b.iter(|| {
            decrypt(
                Some(&verifying_key),
                &encrypted_content,
                Decrypt::Session(key),
            )
            .unwrap();
        })
    });
}

fn hmac_decrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = generate_fingerprint();
    let (hmac_key, key) = generate_dh_keys();

    let content = vec![0u8; 5_000_000];

    let (mut encrypted_content, _) =
        encrypt(fingerprint, content, Encrypt::Hmac(hmac_key, key, 0)).unwrap();

    extract_components_mut(0, &mut encrypted_content);

    c.bench_function("hmac_decrypt", |b| {
        b.iter(|| {
            decrypt(
                Some(&verifying_key),
                &encrypted_content,
                Decrypt::Hmac(hmac_key, key),
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
        Encrypt::Dh(sender_priv_key, &pub_keys),
    )
    .unwrap();

    let content_key = match extract_components_mut(0, &mut encrypted_content) {
        Components::Dh(key) => key,
        _ => unreachable!(),
    };

    c.bench_function("dh_decrypt", |b| {
        b.iter(|| {
            decrypt(
                Some(&verifying_key),
                &encrypted_content,
                Decrypt::Dh(content_key, sender_pub_key, receiver_priv_key),
            )
            .unwrap();
        })
    });
}

criterion_group!(
    benches,
    session_encrypt_benchmark,
    hmac_encrypt_benchmark,
    dh_encrypt_benchmark,
    dh_encrypt_multi_recipient_benchmark,
    extract_components_benchmark,
    extract_components_mut_benchmark,
    session_decrypt_benchmark,
    hmac_decrypt_benchmark,
    dh_decrypt_benchmark,
);

criterion_main!(benches);
