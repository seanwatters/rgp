/*
ordinal_crypto is the cryptography library for the Ordinal Protocol

Copyright (C) 2023  sean watters

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

use lazy_static::lazy_static;

lazy_static! {
    static ref PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK: (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
        [u8; 64],
        [u8; 24],
        [u8; 32],
        [u8; 32],
    ) = {
        let (priv_exchange_key, pub_exchange_key) = ordinal_crypto::generate_exchange_keys();
        let (signing_key, verifying_key) = ordinal_crypto::generate_signing_keys();

        let content = vec![0u8; 1024];

        let signature = ordinal_crypto::sign_content(content.clone(), signing_key);

        let (nonce, key_sets, encrypted_content, sender_public_key) =
            ordinal_crypto::encrypt_and_sign_content(
                signing_key,
                content.clone(),
                pub_exchange_key.to_vec(),
            )
            .unwrap();

        let mut encrypted_content_key: [u8; 32] = [0u8; 32];
        encrypted_content_key[0..32].copy_from_slice(&key_sets[32..64]);

        (
            priv_exchange_key,
            pub_exchange_key,
            signing_key,
            verifying_key,
            content,
            encrypted_content,
            signature,
            nonce,
            encrypted_content_key,
            sender_public_key,
        )
    };
}

fn string_to_32_bytes_benchmark(c: &mut Criterion) {
    c.bench_function("string_to_32_bytes", |b| {
        let val = "benching string to 32 bytes".to_string();

        b.iter(move || {
            ordinal_crypto::string_to_32_bytes(val.clone());
        })
    });
}

fn encode_key_to_string_encrypted_benchmark(c: &mut Criterion) {
    c.bench_function("encode_key_to_string_encrypted", |b| {
        let val = "benching key to encrypted string".to_string();
        let key = [0u8; 32];

        b.iter(move || {
            ordinal_crypto::encode_key_to_string_encrypted(key, val.clone());
        })
    });
}

fn decode_key_from_string_benchmark(c: &mut Criterion) {
    c.bench_function("decode_key_from_string", |b| {
        let val = ordinal_crypto::encode_key_to_string_encrypted(
            [0u8; 32],
            "benching decode 32 byte key".to_string(),
        );

        b.iter(move || {
            ordinal_crypto::decode_key_from_string(val.clone());
        })
    });
}

fn encode_key_to_string_benchmark(c: &mut Criterion) {
    let (_, _, sign, _, _, _, _, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("encode_key_to_string", |b| {
        b.iter(move || {
            ordinal_crypto::encode_key_to_string(*sign);
        })
    });
}

fn block_encrypt_key_benchmark(c: &mut Criterion) {
    let (pub_key, priv_key, _, _, _, _, _, _, _, _) =
        &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("block_encrypt_key", |b| {
        b.iter(|| {
            ordinal_crypto::block_encrypt_key(*pub_key, *priv_key);
        })
    });
}

fn block_decrypt_key_benchmark(c: &mut Criterion) {
    let (pub_key, priv_key, _, _, _, _, _, _, _, _) =
        &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("block_decrypt_key", |b| {
        b.iter(|| {
            ordinal_crypto::block_decrypt_key(*pub_key, *priv_key);
        })
    });
}

fn block_encrypt_signature_benchmark(c: &mut Criterion) {
    let (pub_key, _, _, _, _, _, sig, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("block_encrypt_signature", |b| {
        b.iter(|| {
            ordinal_crypto::block_encrypt_signature(*pub_key, *sig);
        })
    });
}

fn block_decrypt_signature_benchmark(c: &mut Criterion) {
    let (pub_key, _, _, _, _, _, sig, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("block_decrypt_signature", |b| {
        b.iter(|| {
            ordinal_crypto::block_decrypt_signature(*pub_key, *sig);
        })
    });
}

fn generate_signing_keys_benchmark(c: &mut Criterion) {
    c.bench_function("generate_signing_keys", |b| {
        b.iter(move || {
            ordinal_crypto::generate_signing_keys();
        })
    });
}

fn sign_content_benchmark(c: &mut Criterion) {
    let (_, _, sign, _, _, enc, _, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("sign_content", |b| {
        b.iter(move || {
            ordinal_crypto::sign_content(enc.clone(), *sign);
        })
    });
}

fn verify_signature_benchmark(c: &mut Criterion) {
    let (_, _, _, ver, cont, _, sig, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("verify_signature", |b| {
        b.iter(move || {
            ordinal_crypto::verify_signature(*sig, *ver, cont.clone()).unwrap();
        })
    });
}

fn generate_exchange_keys_benchmark(c: &mut Criterion) {
    c.bench_function("generate_exchange_keys", |b| {
        b.iter(move || {
            ordinal_crypto::generate_exchange_keys();
        })
    });
}

fn encrypt_and_sign_content_benchmark(c: &mut Criterion) {
    let (pub_key, _, sign, _, cont, _, _, _, _, _) = &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("encrypt_and_sign_content", |b| {
        b.iter(move || {
            ordinal_crypto::encrypt_and_sign_content(*sign, cont.clone(), pub_key.to_vec())
                .unwrap();
        })
    });
}

fn decrypt_content_benchmark(c: &mut Criterion) {
    let (_, priv_key, _, _, _, enc, _, nonce, eck, spk) =
        &*PUB_PRIV_SIGN_VER_CONT_ENC_SIG_NONCE_ECK_SPK;

    c.bench_function("decrypt_content", |b| {
        b.iter(move || {
            ordinal_crypto::decrypt_content(*spk, *priv_key, *eck, *nonce, enc.clone()).unwrap();
        })
    });
}

criterion_group!(
    benches,
    string_to_32_bytes_benchmark,
    encode_key_to_string_encrypted_benchmark,
    decode_key_from_string_benchmark,
    encode_key_to_string_benchmark,
    block_encrypt_key_benchmark,
    block_decrypt_key_benchmark,
    block_encrypt_signature_benchmark,
    block_decrypt_signature_benchmark,
    generate_signing_keys_benchmark,
    sign_content_benchmark,
    decode_key_from_string_benchmark,
    encode_key_to_string_benchmark,
    verify_signature_benchmark,
    generate_exchange_keys_benchmark,
    encrypt_and_sign_content_benchmark,
    decrypt_content_benchmark,
);

criterion_main!(benches);
