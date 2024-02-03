/*
ordinal_crypto is the cryptography library for the Ordinal Platform

Copyright (C) 2024 sean watters

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

use criterion::{criterion_group, criterion_main, Criterion};

fn hash_str_benchmark(c: &mut Criterion) {
    let val = "benching string to 32 bytes";

    c.bench_function("hash_str", |b| {
        b.iter(|| {
            ordinal_crypto::hash_str(val);
        })
    });
}

fn bytes_32_encode_benchmark(c: &mut Criterion) {
    let pub_key = [0u8; 32];

    c.bench_function("bytes_32_encode", |b| {
        b.iter(|| {
            ordinal_crypto::bytes_32::encode(&pub_key);
        })
    });
}

fn bytes_32_decode_benchmark(c: &mut Criterion) {
    let str_key = ordinal_crypto::bytes_32::encode(&[0u8; 32]);

    c.bench_function("bytes_32_decode", |b| {
        b.iter(|| {
            ordinal_crypto::bytes_32::decode(&str_key).unwrap();
        })
    });
}

fn aead_encrypt_benchmark(c: &mut Criterion) {
    let key = [0u8; 32];
    let content = [0u8; 12_140];

    c.bench_function("aead_encrypt", |b| {
        b.iter(|| {
            ordinal_crypto::aead::encrypt(&key, &content).unwrap();
        })
    });
}

fn aead_decrypt_benchmark(c: &mut Criterion) {
    let key = [0u8; 32];
    let content = [0u8; 12_140];

    let encrypted_content = ordinal_crypto::aead::encrypt(&key, &content).unwrap();

    c.bench_function("aead_decrypt", |b| {
        b.iter(|| {
            ordinal_crypto::aead::decrypt(&key, &encrypted_content).unwrap();
        })
    });
}

fn signature_generate_fingerprint_benchmark(c: &mut Criterion) {
    c.bench_function("signature_generate_fingerprint", |b| {
        b.iter(|| {
            ordinal_crypto::signature::generate_fingerprint();
        })
    });
}

fn signature_sign_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = ordinal_crypto::signature::generate_fingerprint();
    let content = [0u8; 12_140];

    c.bench_function("signature_sign", |b| {
        b.iter(|| {
            ordinal_crypto::signature::sign(&fingerprint, &content);
        })
    });
}

fn signature_verify_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
    let content = [0u8; 12_140];

    let signature = ordinal_crypto::signature::sign(&fingerprint, &content);

    c.bench_function("signature_verify", |b| {
        b.iter(|| {
            ordinal_crypto::signature::verify(&signature, &verifying_key, &content).unwrap();
        })
    });
}

fn generate_exchange_keys_benchmark(c: &mut Criterion) {
    c.bench_function("generate_exchange_keys", |b| {
        b.iter(|| {
            ordinal_crypto::generate_exchange_keys();
        })
    });
}

fn content_encrypt_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = ordinal_crypto::signature::generate_fingerprint();
    let content = vec![0u8; 12_140];
    let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
    let pub_keys = vec![pub_key];

    c.bench_function("content_encrypt", |b| {
        b.iter(|| {
            ordinal_crypto::content::encrypt(&fingerprint, &content, pub_keys.clone()).unwrap();
        })
    });
}

fn content_encrypt_multi_recipient_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = ordinal_crypto::signature::generate_fingerprint();
    let content = vec![0u8; 12_140];
    let mut pub_keys = vec![];

    for _ in 0..5000 {
        let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
        pub_keys.push(pub_key)
    }

    c.bench_function("content_encrypt_multi_recipient", |b| {
        b.iter(|| {
            ordinal_crypto::content::encrypt(&fingerprint, &content, pub_keys.clone()).unwrap();
        })
    });
}

fn content_extract_components_for_key_position_benchmark(c: &mut Criterion) {
    let (fingerprint, _) = ordinal_crypto::signature::generate_fingerprint();
    let content = vec![0u8; 12_140];
    let mut pub_keys = vec![];

    for _ in 0..5000 {
        let (_, pub_key) = ordinal_crypto::generate_exchange_keys();
        pub_keys.push(pub_key)
    }

    let encrypted_content =
        ordinal_crypto::content::encrypt(&fingerprint, &content, pub_keys).unwrap();

    c.bench_function("content_extract_components_for_key_position", |b| {
        b.iter(|| {
            ordinal_crypto::content::extract_components_for_key_position(&encrypted_content, 0)
                .unwrap();
        })
    });
}

fn decrypt_content_benchmark(c: &mut Criterion) {
    let (fingerprint, verifying_key) = ordinal_crypto::signature::generate_fingerprint();
    let content = vec![0u8; 12_140];
    let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();

    let pub_keys = vec![pub_key];

    let encrypted_content =
        ordinal_crypto::content::encrypt(&fingerprint, &content, pub_keys).unwrap();

    let (encrypted_content, encrypted_key) =
        ordinal_crypto::content::extract_components_for_key_position(&encrypted_content, 0)
            .unwrap();

    c.bench_function("decrypt_content", |b| {
        b.iter(|| {
            ordinal_crypto::content::decrypt(
                Some(&verifying_key),
                priv_key,
                &encrypted_key,
                &encrypted_content,
            )
            .unwrap();
        })
    });
}

criterion_group!(
    benches,
    // hash_str_benchmark,
    // bytes_32_encode_benchmark,
    // bytes_32_decode_benchmark,
    // aead_encrypt_benchmark,
    // aead_decrypt_benchmark,
    // signature_generate_fingerprint_benchmark,
    // signature_sign_benchmark,
    // signature_verify_benchmark,
    // generate_exchange_keys_benchmark,
    // content_encrypt_benchmark,
    content_encrypt_multi_recipient_benchmark,
    content_extract_components_for_key_position_benchmark,
    decrypt_content_benchmark,
);

criterion_main!(benches);
