use ext_php_rs::binary::Binary;
use ext_php_rs::boxed::ZBox;
use ext_php_rs::exception::PhpException;
use ext_php_rs::prelude::*;
use ext_php_rs::types::ZendHashTable;

trait SigOps {
    fn generate() -> (Vec<u8>, Vec<u8>);
    fn keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String>;
    fn sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(
        vk: &[u8],
        sig: &[u8],
        msg: &[u8],
    ) -> Result<bool, String>;
    fn seed_len() -> usize;
    fn vk_len() -> usize;
}

macro_rules! define_sig_variant {
    (
        $sk:ident, $sk_name:literal,
        $vk:ident, $vk_name:literal,
        $algo:ident, $algo_name:literal,
        $ops:ty
    ) => {
        #[php_class]
        #[php(name = $sk_name)]
        #[derive(Clone)]
        pub struct $sk {
            seed: Vec<u8>,
        }

        #[php_impl]
        impl $sk {
            pub fn bytes(&self) -> Binary<u8> {
                Binary::new(self.seed.clone())
            }

            pub fn sign(
                &self,
                message: Binary<u8>,
            ) -> PhpResult<Binary<u8>> {
                <$ops>::sign(&self.seed, &message)
                    .map(Binary::new)
                    .map_err(|e| PhpException::default(e))
            }

            pub fn fromBytes(bytes: Binary<u8>) -> PhpResult<Self> {
                let expected = <$ops>::seed_len();
                if bytes.len() != expected {
                    return Err(PhpException::default(format!(
                        "Invalid seed length: expected {}, got {}",
                        expected,
                        bytes.len()
                    )));
                }
                Ok(Self {
                    seed: bytes.to_vec(),
                })
            }
        }

        #[php_class]
        #[php(name = $vk_name)]
        #[derive(Clone)]
        pub struct $vk {
            bytes: Vec<u8>,
        }

        #[php_impl]
        impl $vk {
            pub fn bytes(&self) -> Binary<u8> {
                Binary::new(self.bytes.clone())
            }

            pub fn verify(
                &self,
                signature: Binary<u8>,
                message: Binary<u8>,
            ) -> PhpResult<bool> {
                <$ops>::verify(&self.bytes, &signature, &message)
                    .map_err(|e| PhpException::default(e))
            }

            pub fn fromBytes(bytes: Binary<u8>) -> PhpResult<Self> {
                let expected = <$ops>::vk_len();
                if bytes.len() != expected {
                    return Err(PhpException::default(format!(
                        "Invalid key length: expected {}, got {}",
                        expected,
                        bytes.len()
                    )));
                }
                Ok(Self {
                    bytes: bytes.to_vec(),
                })
            }
        }

        #[php_class]
        #[php(name = $algo_name)]
        pub struct $algo;

        #[php_impl]
        impl $algo {
            pub fn generateKeypair(
            ) -> PhpResult<ZBox<ZendHashTable>> {
                let (seed, vk_bytes) = <$ops>::generate();
                let sk = $sk { seed };
                let vk = $vk { bytes: vk_bytes };
                let mut ht = ZendHashTable::new();
                ht.push(sk).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                ht.push(vk).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                Ok(ht)
            }

            pub fn keypairFromSeed(
                seed: Binary<u8>,
            ) -> PhpResult<ZBox<ZendHashTable>> {
                let (sk_seed, vk_bytes) =
                    <$ops>::keypair_from_seed(&seed)
                        .map_err(|e| PhpException::default(e))?;
                let sk = $sk { seed: sk_seed };
                let vk = $vk { bytes: vk_bytes };
                let mut ht = ZendHashTable::new();
                ht.push(sk).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                ht.push(vk).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                Ok(ht)
            }
        }
    };
}

mod mldsa_ops {
    use super::SigOps;
    use ml_dsa::signature::{Signer, Verifier};

    macro_rules! impl_mldsa {
        ($ops:ident, $param:ty, $vk_len:literal) => {
            pub struct $ops;

            impl SigOps for $ops {
                fn generate() -> (Vec<u8>, Vec<u8>) {
                    use ml_dsa::KeyGen;
                    use ml_dsa::signature::Keypair;
                    let mut rng = rand::rng();
                    let kp = <$param>::key_gen(&mut rng);
                    let seed = kp.to_seed().to_vec();
                    let vk_enc = kp.verifying_key().encode();
                    let vk_s: &[u8] = &vk_enc;
                    (seed, vk_s.to_vec())
                }

                fn keypair_from_seed(
                    seed: &[u8],
                ) -> Result<(Vec<u8>, Vec<u8>), String> {
                    use ml_dsa::KeyGen;
                    use ml_dsa::signature::Keypair;
                    let seed_ref: &ml_dsa::Seed =
                        seed.try_into().map_err(|_| {
                            format!(
                                "Invalid seed length: expected 32, got {}",
                                seed.len()
                            )
                        })?;
                    let kp = <$param>::from_seed(seed_ref);
                    let vk_enc = kp.verifying_key().encode();
                    let vk_s: &[u8] = &vk_enc;
                    Ok((seed.to_vec(), vk_s.to_vec()))
                }

                fn sign(
                    seed: &[u8],
                    msg: &[u8],
                ) -> Result<Vec<u8>, String> {
					use ml_dsa::KeyGen;
                    let seed_ref: &ml_dsa::Seed =
                        seed.try_into().map_err(|_| {
                            "Invalid seed length".to_string()
                        })?;
                    let sk = <$param>::from_seed(
                            seed_ref,
                        );
                    let sig = Signer::sign(&sk, msg);
                    let enc = sig.encode();
                    let s: &[u8] = &enc;
                    Ok(s.to_vec())
                }

                fn verify(
                    vk: &[u8],
                    sig: &[u8],
                    msg: &[u8],
                ) -> Result<bool, String> {
                    let vk_enc: &ml_dsa::EncodedVerifyingKey<
                        $param,
                    > = vk.try_into().map_err(|_| {
                        "Invalid verifying key length".to_string()
                    })?;
                    let vk =
                        ml_dsa::VerifyingKey::<$param>::decode(
                            vk_enc,
                        );
                    let sig_enc: &ml_dsa::EncodedSignature<
                        $param,
                    > = sig.try_into().map_err(|_| {
                        "Invalid signature length".to_string()
                    })?;
                    let sig =
                        ml_dsa::Signature::<$param>::decode(
                            sig_enc,
                        )
                        .ok_or_else(|| {
                            "Invalid signature".to_string()
                        })?;
                    Ok(vk.verify(msg, &sig).is_ok())
                }

                fn seed_len() -> usize {
                    32
                }

                fn vk_len() -> usize {
                    $vk_len
                }
            }
        };
    }

    impl_mldsa!(MlDsa44Ops, ml_dsa::MlDsa44, 1312);
    impl_mldsa!(MlDsa65Ops, ml_dsa::MlDsa65, 1952);
    impl_mldsa!(MlDsa87Ops, ml_dsa::MlDsa87, 2592);
}

define_sig_variant!(
    MlDsa44Sk,
    "PQCrypto\\MLDSA44\\SigningKey",
    MlDsa44Vk,
    "PQCrypto\\MLDSA44\\VerifyingKey",
    MlDsa44Algo,
    "PQCrypto\\MLDSA44",
    mldsa_ops::MlDsa44Ops
);

define_sig_variant!(
    MlDsa65Sk,
    "PQCrypto\\MLDSA65\\SigningKey",
    MlDsa65Vk,
    "PQCrypto\\MLDSA65\\VerifyingKey",
    MlDsa65Algo,
    "PQCrypto\\MLDSA65",
    mldsa_ops::MlDsa65Ops
);

define_sig_variant!(
    MlDsa87Sk,
    "PQCrypto\\MLDSA87\\SigningKey",
    MlDsa87Vk,
    "PQCrypto\\MLDSA87\\VerifyingKey",
    MlDsa87Algo,
    "PQCrypto\\MLDSA87",
    mldsa_ops::MlDsa87Ops
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlhDsaVariant {
    Shake128f,
    Shake128s,
    Shake192f,
    Shake192s,
    Shake256f,
    Shake256s,
    Sha2_128f,
    Sha2_128s,
    Sha2_192f,
    Sha2_192s,
    Sha2_256f,
    Sha2_256s,
}

impl SlhDsaVariant {
    fn from_params(
        hash: &str,
        speed: &str,
    ) -> Result<Self, String> {
        let hash_lower = hash.to_lowercase();
        let speed_lower = speed.to_lowercase();
        let fast = match speed_lower.as_str() {
            "fast" | "f" => true,
            "small" | "s" | "compact" => false,
            _ => {
                return Err(format!(
                    "Invalid speed: '{speed}'. Use 'fast' or 'small'."
                ))
            }
        };
        match (hash_lower.as_str(), fast) {
            ("shake128", true) => Ok(Self::Shake128f),
            ("shake128", false) => Ok(Self::Shake128s),
            ("shake192", true) => Ok(Self::Shake192f),
            ("shake192", false) => Ok(Self::Shake192s),
            ("shake256", true) => Ok(Self::Shake256f),
            ("shake256", false) => Ok(Self::Shake256s),
            ("sha2-128" | "sha2_128" | "sha2128", true) => {
                Ok(Self::Sha2_128f)
            }
            ("sha2-128" | "sha2_128" | "sha2128", false) => {
                Ok(Self::Sha2_128s)
            }
            ("sha2-192" | "sha2_192" | "sha2192", true) => {
                Ok(Self::Sha2_192f)
            }
            ("sha2-192" | "sha2_192" | "sha2192", false) => {
                Ok(Self::Sha2_192s)
            }
            ("sha2-256" | "sha2_256" | "sha2256", true) => {
                Ok(Self::Sha2_256f)
            }
            ("sha2-256" | "sha2_256" | "sha2256", false) => {
                Ok(Self::Sha2_256s)
            }
            _ => Err(format!(
                "Unknown hash: '{hash}'. Use 'shake128', \
                 'shake192', 'shake256', 'sha2-128', 'sha2-192', \
                 or 'sha2-256'."
            )),
        }
    }

    fn sk_len(self) -> usize {
        match self {
            Self::Shake128f | Self::Shake128s | Self::Sha2_128f
            | Self::Sha2_128s => 64,
            Self::Shake192f | Self::Shake192s | Self::Sha2_192f
            | Self::Sha2_192s => 96,
            Self::Shake256f | Self::Shake256s | Self::Sha2_256f
            | Self::Sha2_256s => 128,
        }
    }

    fn vk_len(self) -> usize {
        match self {
            Self::Shake128f | Self::Shake128s | Self::Sha2_128f
            | Self::Sha2_128s => 32,
            Self::Shake192f | Self::Shake192s | Self::Sha2_192f
            | Self::Sha2_192s => 48,
            Self::Shake256f | Self::Shake256s | Self::Sha2_256f
            | Self::Sha2_256s => 64,
        }
    }
}

use slh_dsa::ParameterSet;

fn slhdsa_generate<P: ParameterSet>() -> (Vec<u8>, Vec<u8>) {
    use slh_dsa::signature::Keypair;
    let mut rng = rand::rng();
    let sk = slh_dsa::SigningKey::<P>::new(&mut rng);
    let vk = sk.verifying_key();
    (sk.to_vec(), vk.to_vec())
}

fn slhdsa_sign<P: ParameterSet>(
    sk_bytes: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, String> {
    use slh_dsa::signature::Signer;
    let sk = slh_dsa::SigningKey::<P>::try_from(sk_bytes)
        .map_err(|e| format!("Invalid signing key: {e}"))?;
    let sig = Signer::sign(&sk, msg);
    Ok(sig.to_vec())
}

fn slhdsa_verify<P: ParameterSet>(
    vk_bytes: &[u8],
    sig_bytes: &[u8],
    msg: &[u8],
) -> Result<bool, String> {
    use slh_dsa::signature::Verifier;
    let vk = slh_dsa::VerifyingKey::<P>::try_from(vk_bytes)
        .map_err(|e| format!("Invalid verifying key: {e}"))?;
    let sig = slh_dsa::Signature::<P>::try_from(sig_bytes)
        .map_err(|e| format!("Invalid signature: {e}"))?;
    Ok(vk.verify(msg, &sig).is_ok())
}

macro_rules! slhdsa_dispatch {
    ($variant:expr, $func:ident $(, $arg:expr)*) => {
        match $variant {
            SlhDsaVariant::Shake128f => $func::<slh_dsa::Shake128f>($($arg),*),
            SlhDsaVariant::Shake128s => $func::<slh_dsa::Shake128s>($($arg),*),
            SlhDsaVariant::Shake192f => $func::<slh_dsa::Shake192f>($($arg),*),
            SlhDsaVariant::Shake192s => $func::<slh_dsa::Shake192s>($($arg),*),
            SlhDsaVariant::Shake256f => $func::<slh_dsa::Shake256f>($($arg),*),
            SlhDsaVariant::Shake256s => $func::<slh_dsa::Shake256s>($($arg),*),
            SlhDsaVariant::Sha2_128f => $func::<slh_dsa::Sha2_128f>($($arg),*),
            SlhDsaVariant::Sha2_128s => $func::<slh_dsa::Sha2_128s>($($arg),*),
            SlhDsaVariant::Sha2_192f => $func::<slh_dsa::Sha2_192f>($($arg),*),
            SlhDsaVariant::Sha2_192s => $func::<slh_dsa::Sha2_192s>($($arg),*),
            SlhDsaVariant::Sha2_256f => $func::<slh_dsa::Sha2_256f>($($arg),*),
            SlhDsaVariant::Sha2_256s => $func::<slh_dsa::Sha2_256s>($($arg),*),
        }
    };
}

#[php_class]
#[php(name = "PQCrypto\\SLHDSA\\SigningKey")]
#[derive(Clone)]
pub struct SlhDsaSigningKey {
    variant: SlhDsaVariant,
    seed: Vec<u8>,
}

#[php_impl]
impl SlhDsaSigningKey {
    pub fn bytes(&self) -> Binary<u8> {
        Binary::new(self.seed.clone())
    }

    pub fn sign(
        &self,
        message: Binary<u8>,
    ) -> PhpResult<Binary<u8>> {
        slhdsa_dispatch!(
            self.variant,
            slhdsa_sign,
            &self.seed,
            message.as_ref()
        )
        .map(Binary::new)
        .map_err(PhpException::default)
    }
}

#[php_class]
#[php(name = "PQCrypto\\SLHDSA\\VerifyingKey")]
#[derive(Clone)]
pub struct SlhDsaVerifyingKey {
    variant: SlhDsaVariant,
    bytes: Vec<u8>,
}

#[php_impl]
impl SlhDsaVerifyingKey {
    pub fn bytes(&self) -> Binary<u8> {
        Binary::new(self.bytes.clone())
    }

    pub fn verify(
        &self,
        signature: Binary<u8>,
        message: Binary<u8>,
    ) -> PhpResult<bool> {
        slhdsa_dispatch!(
            self.variant,
            slhdsa_verify,
            &self.bytes,
            signature.as_ref(),
            message.as_ref()
        )
        .map_err(PhpException::default)
    }
}

#[php_class]
#[php(name = "PQCrypto\\SLHDSA")]
#[derive(Clone)]
pub struct SlhDsa {
    variant: SlhDsaVariant,
}

#[php_impl]
impl SlhDsa {
    pub fn __construct(
        hash: String,
        speed: String,
    ) -> PhpResult<Self> {
        let variant = SlhDsaVariant::from_params(&hash, &speed)
            .map_err(PhpException::default)?;
        Ok(Self { variant })
    }

    pub fn generateKeypair(
        &self,
    ) -> PhpResult<ZBox<ZendHashTable>> {
        let (sk_bytes, vk_bytes) =
            slhdsa_dispatch!(self.variant, slhdsa_generate);
        let sk = SlhDsaSigningKey {
            variant: self.variant,
            seed: sk_bytes,
        };
        let vk = SlhDsaVerifyingKey {
            variant: self.variant,
            bytes: vk_bytes,
        };
        let mut ht = ZendHashTable::new();
        ht.push(sk)
            .map_err(|e| PhpException::default(e.to_string()))?;
        ht.push(vk)
            .map_err(|e| PhpException::default(e.to_string()))?;
        Ok(ht)
    }

    pub fn importSigningKey(
        &self,
        bytes: Binary<u8>,
    ) -> PhpResult<SlhDsaSigningKey> {
        let expected = self.variant.sk_len();
        if bytes.len() != expected {
            return Err(PhpException::default(format!(
                "Invalid key length: expected {}, got {}",
                expected,
                bytes.len()
            )));
        }
        Ok(SlhDsaSigningKey {
            variant: self.variant,
            seed: bytes.to_vec(),
        })
    }

    pub fn importVerifyingKey(
        &self,
        bytes: Binary<u8>,
    ) -> PhpResult<SlhDsaVerifyingKey> {
        let expected = self.variant.vk_len();
        if bytes.len() != expected {
            return Err(PhpException::default(format!(
                "Invalid key length: expected {}, got {}",
                expected,
                bytes.len()
            )));
        }
        Ok(SlhDsaVerifyingKey {
            variant: self.variant,
            bytes: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::mldsa_ops::{MlDsa44Ops, MlDsa65Ops, MlDsa87Ops};
    use super::{
        slhdsa_generate, slhdsa_sign, slhdsa_verify,
        SlhDsaVariant, SigOps,
    };

    fn run_sig_test<T: SigOps>(seed_len: usize, vk_len: usize) {
        let (seed, vk) = T::generate();
        assert_eq!(seed.len(), seed_len);
        assert_eq!(vk.len(), vk_len);

        let sig = T::sign(&seed, b"test msg").unwrap();
        assert!(T::verify(&vk, &sig, b"test msg").unwrap());
        assert!(!T::verify(&vk, &sig, b"wrong").unwrap());
        assert!(T::sign(b"short", b"msg").is_err());

        let (seed2, vk2) = T::keypair_from_seed(&seed).unwrap();
        assert_eq!(seed, seed2);
        assert_eq!(vk, vk2);

        let sig2 = T::sign(&seed2, b"seed kp test").unwrap();
        assert!(T::verify(&vk2, &sig2, b"seed kp test").unwrap());
        assert!(T::keypair_from_seed(b"short").is_err());
    }

    #[test]
    fn mldsa44() { run_sig_test::<MlDsa44Ops>(32, 1312); }

    #[test]
    fn mldsa65() { run_sig_test::<MlDsa65Ops>(32, 1952); }

    #[test]
    fn mldsa87() { run_sig_test::<MlDsa87Ops>(32, 2592); }

    fn run_slhdsa_test(hash: &str, speed: &str, sk_len: usize, vk_len: usize) {
        let v = SlhDsaVariant::from_params(hash, speed).unwrap();
        let (sk, vk) = slhdsa_dispatch!(v, slhdsa_generate);
        assert_eq!(sk.len(), sk_len);
        assert_eq!(vk.len(), vk_len);
        let sig =
            slhdsa_dispatch!(v, slhdsa_sign, &sk, b"msg").unwrap();
        assert!(
            slhdsa_dispatch!(v, slhdsa_verify, &vk, &sig, b"msg")
                .unwrap()
        );
        assert!(
            !slhdsa_dispatch!(v, slhdsa_verify, &vk, &sig, b"bad")
                .unwrap()
        );
    }

    #[test]
    fn slhdsa_shake128f() {
        run_slhdsa_test("shake128", "fast", 64, 32);
    }

    #[test]
    fn slhdsa_shake128s() {
        run_slhdsa_test("shake128", "small", 64, 32);
    }

    #[test]
    fn slhdsa_shake256f() {
        run_slhdsa_test("shake256", "fast", 128, 64);
    }

    #[test]
    fn slhdsa_sha2_128f() {
        run_slhdsa_test("sha2-128", "fast", 64, 32);
    }

    #[test]
    fn slhdsa_rejects_invalid_params() {
        assert!(SlhDsaVariant::from_params("md5", "fast").is_err());
        assert!(
            SlhDsaVariant::from_params("shake128", "turbo").is_err()
        );
    }
}
