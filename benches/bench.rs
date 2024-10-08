#![feature(test)]
extern crate test;

use std::time::SystemTime;
use std::convert::TryInto;

use test::Bencher;

use rand_core::{SeedableRng, RngCore};
use rand_chacha::ChaCha12Rng;

use pi_rand::{xor_encrypt, xor_encrypt_confusion, xor_unencrypt_clarity};

#[bench]
fn bench_xor_encrypt(b: &mut Bencher) {
    b.iter(move || {
        let key = 0xffabcdeffedcba00_u64.to_le_bytes();
        for n in 0x1fffffffffffffff_u64..0x1fffffffffffffff_u64 + 10000 {
            let vec = xor_encrypt(xor_encrypt(n.to_le_bytes(), key).unwrap(), key).unwrap();
            assert_eq!(n,
                       u64::from_le_bytes(vec.as_slice().try_into().unwrap()));
        }
    });
}

#[bench]
fn bench_xor_encrypt_confusion(b: &mut Bencher) {
    b.iter(move || {
        let key = 0xffabcdeffedcba00_u64.to_le_bytes();
        for n in 0x1fffffffffffffff_u64..0x1fffffffffffffff_u64 + 10000 {
            let vec = xor_unencrypt_clarity(xor_encrypt_confusion(n.to_le_bytes(), key).unwrap(), key).unwrap();
            assert_eq!(n,
                       u64::from_le_bytes(vec.as_slice().try_into().unwrap()));
        }
    });
}

#[bench]
fn bench_chacha12_next_u32(b: &mut Bencher) {
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let mut rng = ChaCha12Rng::seed_from_u64(seed.as_millis() as u64);

    b.iter(move || {
        let mut n = 0;
        for _ in 0..1000000 {
            n = rng.next_u32();
        }
        assert!(n > 0);
    });
}

#[bench]
fn bench_chacha12_next_u64(b: &mut Bencher) {
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let mut rng = ChaCha12Rng::seed_from_u64(seed.as_millis() as u64);

    b.iter(move || {
        let mut n = 0;
        for _ in 0..1000000 {
            n = rng.next_u64();
        }
        assert!(n > 0);
    });
}
