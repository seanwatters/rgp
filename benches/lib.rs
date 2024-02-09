/*
Copyright (c) 2024 sean watters

Licensed under the MIT license <LICENSE-MIT or https://opensource.org/licenses/MIT>.
This file may not be copied, modified, or distributed except according to those terms.
*/

use criterion::{criterion_group, criterion_main, Criterion};

fn signature_generate_fingerprint_benchmark(c: &mut Criterion) {
    c.bench_function("signature_generate_fingerprint", |b| {
        b.iter(|| {
            rgp::signature::generate_fingerprint();
        })
    });
}

fn signature_sign_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::signature::generate_fingerprint();
    let content = [0u8; 8_000_000];

    c.bench_function("signature_sign", |b| {
        b.iter(|| {
            rgp::signature::sign(&fingerprint, &content);
        })
    });
}

fn signature_verify_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();
    let content = [0u8; 8_000_000];

    let signature = rgp::signature::sign(&fingerprint, &content);

    c.bench_function("signature_verify", |b| {
        b.iter(|| {
            rgp::signature::verify(&signature, &verifying_key, &content).unwrap();
        })
    });
}

fn generate_exchange_keys_benchmark(c: &mut Criterion) {
    c.bench_function("generate_exchange_keys", |b| {
        b.iter(|| {
            rgp::generate_exchange_keys();
        })
    });
}

fn content_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::signature::generate_fingerprint();
    let content = vec![0u8; 8_000_000];
    let (_, pub_key) = rgp::generate_exchange_keys();
    let pub_keys = vec![pub_key];

    c.bench_function("content_encrypt", |b| {
        b.iter(|| {
            rgp::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();
        })
    });
}

fn content_encrypt_multi_recipient_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::signature::generate_fingerprint();
    let content = vec![0u8; 8_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = rgp::generate_exchange_keys();
        pub_keys.push(pub_key)
    }

    c.bench_function("content_encrypt_multi_recipient", |b| {
        b.iter(|| {
            rgp::content::encrypt(fingerprint, content.clone(), &pub_keys).unwrap();
        })
    });
}

fn content_extract_content_for_key_position_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = rgp::signature::generate_fingerprint();
    let content = vec![0u8; 8_000_000];
    let mut pub_keys = vec![];

    for _ in 0..20_000 {
        let (_, pub_key) = rgp::generate_exchange_keys();
        pub_keys.push(pub_key)
    }

    let encrypted_content = rgp::content::encrypt(fingerprint, content, &pub_keys).unwrap();

    c.bench_function("content_extract_content_for_key_position", |b| {
        b.iter(|| {
            rgp::content::extract_content_for_key_position(&mut encrypted_content.clone(), 0)
                .unwrap();
        })
    });
}

fn decrypt_content_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = rgp::signature::generate_fingerprint();
    let content = vec![0u8; 8_000_000];
    let (priv_key, pub_key) = rgp::generate_exchange_keys();

    let pub_keys = vec![pub_key];

    let mut encrypted_content = rgp::content::encrypt(fingerprint, content, &pub_keys).unwrap();

    rgp::content::extract_content_for_key_position(&mut encrypted_content, 0).unwrap();

    c.bench_function("decrypt_content", |b| {
        b.iter(|| {
            rgp::content::decrypt(Some(&verifying_key), priv_key, &encrypted_content).unwrap();
        })
    });
}

criterion_group!(
    benches,
    signature_generate_fingerprint_benchmark,
    signature_sign_benchmark,
    signature_verify_benchmark,
    generate_exchange_keys_benchmark,
    content_encrypt_benchmark,
    content_encrypt_multi_recipient_benchmark,
    content_extract_content_for_key_position_benchmark,
    decrypt_content_benchmark,
);

criterion_main!(benches);
