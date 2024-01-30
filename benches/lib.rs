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

use lazy_static::lazy_static;

lazy_static! {
    static ref PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD: (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Vec<u8>,
        Vec<u8>,
        [u8; 64],
        [u8; 32],
        Vec<u8>,
        Vec<u8>
    ) = {
        let (priv_key, pub_key) = ordinal_crypto::generate_exchange_keys();
        let (fingerprint, verifying_key) = ordinal_crypto::generate_fingerprint();

        let content = vec![0u8; 1024];

        let signature = ordinal_crypto::sign_content(&content, &fingerprint);

        let encrypted_content =
            ordinal_crypto::encrypt_content(&fingerprint, &content, &pub_key.to_vec()).unwrap();

        let key_header_bytes: [u8; 2] = encrypted_content[0..2]
            .try_into()
            .expect("failed to convert bytes");

        let key_count = u16::from_be_bytes(key_header_bytes) as usize;
        let keys_end = key_count * 32 + 2;

        let encrypted_content_key = encrypted_content[2..34]
            .try_into()
            .expect("failed to convert bytes");

        let mut multi_pub_keys = vec![];

        for _ in 0..1000 {
            multi_pub_keys.extend(pub_key)
        }

        let aead_encrypted_content = ordinal_crypto::aead_encrypt(&priv_key, &content).unwrap();

        (
            pub_key,
            priv_key,
            fingerprint,
            verifying_key,
            content,
            encrypted_content[keys_end..].to_vec(),
            signature,
            encrypted_content_key,
            multi_pub_keys,
            aead_encrypted_content,
        )
    };
}

fn str_to_32_bytes_benchmark(c: &mut Criterion) {
    let val = "benching string to 32 bytes";

    c.bench_function("str_to_32_bytes", |b| {
        b.iter(|| {
            ordinal_crypto::str_to_32_bytes(val);
        })
    });
}

fn encode_32_bytes_to_string_benchmark(c: &mut Criterion) {
    let (_, _, fp, _, _, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("encode_32_bytes_to_string", |b| {
        b.iter(|| {
            ordinal_crypto::encode_32_bytes_to_string(fp);
        })
    });
}

fn decode_32_bytes_from_string_benchmark(c: &mut Criterion) {
    let (_, _, fp, _, _, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;
    let str_key = ordinal_crypto::encode_32_bytes_to_string(fp);

    c.bench_function("decode_32_bytes_from_string", |b| {
        b.iter(|| {
            ordinal_crypto::decode_32_bytes_from_string(&str_key).unwrap();
        })
    });
}

fn encrypt_32_bytes_benchmark(c: &mut Criterion) {
    let (pub_key, priv_key, _, _, _, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("encrypt_32_bytes", |b| {
        b.iter(|| {
            ordinal_crypto::encrypt_32_bytes(pub_key, priv_key).unwrap();
        })
    });
}

fn decrypt_32_bytes_benchmark(c: &mut Criterion) {
    let (pub_key, priv_key, _, _, _, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("decrypt_32_bytes", |b| {
        b.iter(|| {
            ordinal_crypto::decrypt_32_bytes(pub_key, priv_key).unwrap();
        })
    });
}

fn aead_encrypt_benchmark(c: &mut Criterion) {
    let (_, priv_key, _, _, cont, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("aead_encrypt", |b| {
        b.iter(|| {
            ordinal_crypto::aead_encrypt(priv_key, cont).unwrap();
        })
    });
}

fn aead_decrypt_benchmark(c: &mut Criterion) {
    let (_, priv_key, _, _, _, _, _, _, _, aead) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("aead_decrypt", |b| {
        b.iter(|| {
            ordinal_crypto::aead_decrypt(priv_key, aead).unwrap();
        })
    });
}

fn generate_fingerprint_benchmark(c: &mut Criterion) {
    c.bench_function("generate_fingerprint", |b| {
        b.iter(|| {
            ordinal_crypto::generate_fingerprint();
        })
    });
}

fn sign_content_benchmark(c: &mut Criterion) {
    let (_, _, fp, _, _, enc, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("sign_content", |b| {
        b.iter(|| {
            ordinal_crypto::sign_content(&enc, fp);
        })
    });
}

fn verify_signature_benchmark(c: &mut Criterion) {
    let (_, _, _, ver, cont, _, sig, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("verify_signature", |b| {
        b.iter(|| {
            ordinal_crypto::verify_signature(sig, ver, &cont).unwrap();
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

fn encrypt_content_benchmark(c: &mut Criterion) {
    let (pub_key, _, fp, _, cont, _, _, _, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("encrypt_content", |b| {
        b.iter(|| {
            ordinal_crypto::encrypt_content(fp, &cont, &pub_key.to_vec()).unwrap();
        })
    });
}

fn encrypt_multi_pub_key_benchmark(c: &mut Criterion) {
    let (_, _, fp, _, cont, _, _, _, mrpk, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("encrypt_multi_pub_key", |b| {
        b.iter(|| {
            ordinal_crypto::encrypt_content(fp, &cont, &mrpk).unwrap();
        })
    });
}

fn decrypt_content_benchmark(c: &mut Criterion) {
    let (_, priv_key, _, ver, _, enc, _, eck, _, _) = &*PUB_PRIV_FP_VER_CONT_ENC_SIG_ECK_MPK_AEAD;

    c.bench_function("decrypt_content", |b| {
        b.iter(|| {
            ordinal_crypto::decrypt_content(Some(ver), *priv_key, eck, &enc).unwrap();
        })
    });
}

criterion_group!(
    benches,
    str_to_32_bytes_benchmark,
    encode_32_bytes_to_string_benchmark,
    decode_32_bytes_from_string_benchmark,
    encrypt_32_bytes_benchmark,
    decrypt_32_bytes_benchmark,
    aead_encrypt_benchmark,
    aead_decrypt_benchmark,
    generate_fingerprint_benchmark,
    sign_content_benchmark,
    verify_signature_benchmark,
    generate_exchange_keys_benchmark,
    encrypt_content_benchmark,
    encrypt_multi_pub_key_benchmark,
    decrypt_content_benchmark,
);

criterion_main!(benches);
