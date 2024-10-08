use std::time::SystemTime;
use std::convert::TryInto;

use rand_core::{SeedableRng, RngCore};
use rand_chacha::ChaCha12Rng;

use pi_rand::xor_encrypt;

#[test]
fn test_chacha12() {
    println!("safe seed: {:?}", xor_encrypt(1727517952591u64.to_le_bytes(), 0x7fffffffffffffff_u64.to_le_bytes()).unwrap());
    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let x = xor_encrypt((time.as_millis() as u64).to_le_bytes(), 0xffabcdeffedcba00_u64.to_le_bytes()).unwrap();
    let y = xor_encrypt(x.clone(), 0xffabcdeffedcba00_u64.to_le_bytes()).unwrap();
    let seed = u64::from_le_bytes(y.as_slice().try_into().unwrap());
    println!("time: {:?}, encrypted: {:?}, unencrypted: {:?}, seed: {:?}", time.as_millis() as u64, x, y, seed);
    let mut rng = ChaCha12Rng::seed_from_u64(seed);

    let mut vec = Vec::with_capacity(1000000);
    for _ in 0..1000000 {
        let n: u64 = rng.next_u64();
        vec.push(n);
    }

    let mut other = ChaCha12Rng::seed_from_u64(seed);
    for n in vec {
        assert_eq!(n, other.next_u64());
    }
}