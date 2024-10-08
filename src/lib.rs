use std::convert::TryInto;
use std::time::SystemTime;
use rand_core::{SeedableRng, RngCore};
use rand_chacha::ChaCha12Rng;

///
/// 密码学安全的随机数生成器
///
pub struct SecureRng(ChaCha12Rng);

impl Default for SecureRng {
    /// 使用当前UTC做为种子，创建密码学安全的随机数生成器
    fn default() -> Self {
        let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Self::with_seed(time.as_millis() as u64)
    }
}

impl SecureRng {
    /// 使用种子创建密码学安全的随机数生成器
    pub fn with_seed(seed: u64) -> Self {
        let inner = ChaCha12Rng::seed_from_u64(seed);
        SecureRng(inner)
    }

    /// 使用指定密钥异或加密的种子，创建密码学安全的随机数生成器
    pub fn with_safe_seed<S, K>(encrypted: S, key: K) -> Self
    where S: AsRef<[u8]>,
          K: AsRef<[u8]>,
    {
        let unencrypted = xor_encrypt(encrypted, key).unwrap();
        let seed = u64::from_le_bytes(unencrypted.as_slice().try_into().unwrap());
        Self::with_seed(seed)
    }

    /// 使用指定密钥异或加密并混淆的种子，创建密码学安全的随机数生成器
    pub fn with_confusion_seed<S, K>(encrypted: S, key: K) -> Self
    where S: AsRef<[u8]>,
          K: AsRef<[u8]>,
    {
        let unencrypted = xor_unencrypt_clarity(encrypted, key).unwrap();
        let seed = u64::from_le_bytes(unencrypted.as_slice().try_into().unwrap());
        Self::with_seed(seed)
    }

    /// 获取一个u32的随机数
    #[inline]
    pub fn get_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    /// 获取一个u64的随机数
    #[inline]
    pub fn get_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
}

///
/// 使用指定的密钥为指定的数据异或加解密
///
#[inline]
pub fn xor_encrypt<T, K>(data: T, key: K) -> Result<Vec<u8>, ()>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let data = data.as_ref();
    let key = key.as_ref();

    if key.as_ref().len() < 8 {
        //密钥长度太小，则立即返回错误
        return Err(());
    }

    let encrypted = data
        .iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect();

    Ok(encrypted)
}

///
/// 使用指定的密钥为指定的数据异或加解密并混淆
///
#[inline]
pub fn xor_encrypt_confusion<T, K>(data: T, key: K) -> Result<Vec<u8>, ()>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let encrypt = xor_encrypt(data, key)?;

    let len = encrypt.len();
    if len % 2 != 0 {
        //长度为奇数，则立即返回错误
        return Err(());
    }

    let half_len = len / 2;
    let mut confused = Vec::with_capacity(len);
    confused.resize(len, 0);
    for i in 0..len {
        if i % 2 != 0 {
            confused[i] = encrypt[i];
            continue;
        } else if i < half_len {
            let j = i + half_len;
            confused[j] = encrypt[i];
            confused[i] = encrypt[j];
        }
    }

    Ok(confused)
}

///
/// 使用指定的密钥为指定的数据明确并异或解密
///
#[inline]
pub fn xor_unencrypt_clarity<T, K>(data: T, key: K) -> Result<Vec<u8>, ()>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let encrypt = data.as_ref();
    let len = encrypt.len();
    if len % 2 != 0 {
        //长度为奇数，则立即返回错误
        return Err(());
    }

    let half_len = len / 2;
    let mut clarified = Vec::with_capacity(len);
    clarified.resize(len, 0);
    for i in 0..len {
        if i % 2 != 0 {
            clarified[i] = encrypt[i];
            continue;
        } else if i < half_len {
            let j = i + half_len;
            clarified[j] = encrypt[i];
            clarified[i] = encrypt[j];
        }
    }

    let unencrypt = xor_encrypt(clarified, key)?;

    Ok(unencrypt)
}

