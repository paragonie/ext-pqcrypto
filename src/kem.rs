use ext_php_rs::binary::Binary;
use ext_php_rs::boxed::ZBox;
use ext_php_rs::exception::PhpException;
use ext_php_rs::prelude::*;
use ext_php_rs::types::ZendHashTable;

trait KemOps {
    fn generate() -> (Vec<u8>, Vec<u8>);
    fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String>;
    fn decapsulate(seed: &[u8], ct: &[u8]) -> Result<Vec<u8>, String>;
    fn seed_len() -> usize;
    fn ek_len() -> usize;
}

macro_rules! define_kem_variant {
    (
        $dk:ident, $dk_name:literal,
        $ek:ident, $ek_name:literal,
        $algo:ident, $algo_name:literal,
        $ops:ty
    ) => {
        #[php_class]
        #[php(name = $dk_name)]
        #[derive(Clone)]
        pub struct $dk {
            seed: Vec<u8>,
        }

        #[php_impl]
        impl $dk {
            pub fn bytes(&self) -> Binary<u8> {
                Binary::new(self.seed.clone())
            }

            pub fn decapsulate(
                &self,
                ciphertext: Binary<u8>,
            ) -> PhpResult<Binary<u8>> {
                <$ops>::decapsulate(&self.seed, &ciphertext)
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
        #[php(name = $ek_name)]
        #[derive(Clone)]
        pub struct $ek {
            bytes: Vec<u8>,
        }

        #[php_impl]
        impl $ek {
            pub fn bytes(&self) -> Binary<u8> {
                Binary::new(self.bytes.clone())
            }

            pub fn encapsulate(
                &self,
            ) -> PhpResult<Vec<Binary<u8>>> {
                let (ss, ct) = <$ops>::encapsulate(&self.bytes)
                    .map_err(|e| PhpException::default(e))?;
                Ok(vec![Binary::new(ss), Binary::new(ct)])
            }

            pub fn fromBytes(bytes: Binary<u8>) -> PhpResult<Self> {
                let expected = <$ops>::ek_len();
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
                let (seed, ek_bytes) = <$ops>::generate();
                let dk = $dk { seed };
                let ek = $ek { bytes: ek_bytes };
                let mut ht = ZendHashTable::new();
                ht.push(dk).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                ht.push(ek).map_err(|e| {
                    PhpException::default(e.to_string())
                })?;
                Ok(ht)
            }
        }
    };
}

mod mlkem_ops {
    use super::KemOps;
    use ml_kem::kem::{
        Decapsulate, Encapsulate, Generate, KeyExport, KeyInit,
    };

    macro_rules! impl_mlkem {
        (
            $ops:ident, $dk_ty:ty, $ek_ty:ty,
            $seed_len:literal, $ek_len:literal
        ) => {
            pub struct $ops;

            impl KemOps for $ops {
                fn generate() -> (Vec<u8>, Vec<u8>) {
                    let mut rng = rand::rng();
                    let dk = <$dk_ty>::generate_from_rng(&mut rng);
                    let seed_bytes = dk.to_bytes();
                    let seed: &[u8] = &seed_bytes;
                    let ek = dk.encapsulation_key();
                    let ek_bytes = ek.to_bytes();
                    let ek_slice: &[u8] = &ek_bytes;
                    (seed.to_vec(), ek_slice.to_vec())
                }

                fn encapsulate(
                    ek_bytes: &[u8],
                ) -> Result<(Vec<u8>, Vec<u8>), String> {
                    let ek_key: &ml_kem::array::Array<u8, _> =
                        ek_bytes.try_into().map_err(|_| {
                            "Invalid encapsulation key length"
                                .to_string()
                        })?;
                    let ek = <$ek_ty>::new(ek_key).map_err(|e| {
                        format!("Invalid encapsulation key: {e}")
                    })?;
                    let mut rng = rand::rng();
                    let (ct, ss) =
                        ek.encapsulate_with_rng(&mut rng);
                    let ct_s: &[u8] = &ct;
                    let ss_s: &[u8] = &ss;
                    Ok((ss_s.to_vec(), ct_s.to_vec()))
                }

                fn decapsulate(
                    seed: &[u8],
                    ct: &[u8],
                ) -> Result<Vec<u8>, String> {
                    let seed_key: &ml_kem::array::Array<u8, _> =
                        seed.try_into().map_err(|_| {
                            "Invalid seed length".to_string()
                        })?;
                    let dk = <$dk_ty>::new(seed_key);
                    let ss = dk.decapsulate_slice(ct).map_err(
                        |_| {
                            "Invalid ciphertext length".to_string()
                        },
                    )?;
                    let ss_s: &[u8] = &ss;
                    Ok(ss_s.to_vec())
                }

                fn seed_len() -> usize {
                    $seed_len
                }

                fn ek_len() -> usize {
                    $ek_len
                }
            }
        };
    }

    impl_mlkem!(
        MlKem512Ops,
        ml_kem::DecapsulationKey512,
        ml_kem::EncapsulationKey512,
        64,
        800
    );
    impl_mlkem!(
        MlKem768Ops,
        ml_kem::DecapsulationKey768,
        ml_kem::EncapsulationKey768,
        64,
        1184
    );
    impl_mlkem!(
        MlKem1024Ops,
        ml_kem::DecapsulationKey1024,
        ml_kem::EncapsulationKey1024,
        64,
        1568
    );
}

mod xwing_ops {
    use super::KemOps;
    use x_wing::kem::{Decapsulate, Encapsulate, KeyExport, Kem};
    use x_wing::{DecapsulationKey, EncapsulationKey, XWingKem};

    pub struct XWingOps;

    impl KemOps for XWingOps {
        fn generate() -> (Vec<u8>, Vec<u8>) {
            let mut rng = rand::rng();
            let (sk, pk) =
                XWingKem::generate_keypair_from_rng(&mut rng);
            let sk_bytes = sk.as_bytes().to_vec();
            let pk_bytes = pk.to_bytes();
            let pk_s: &[u8] = &pk_bytes;
            (sk_bytes, pk_s.to_vec())
        }

        fn encapsulate(
            ek_bytes: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), String> {
            let ek = EncapsulationKey::try_from(ek_bytes)
                .map_err(|e| {
                    format!("Invalid encapsulation key: {e}")
                })?;
            let (ct, ss) = ek.encapsulate();
            let ct_s: &[u8] = &ct;
            let ss_s: &[u8] = &ss;
            Ok((ss_s.to_vec(), ct_s.to_vec()))
        }

        fn decapsulate(
            seed: &[u8],
            ct: &[u8],
        ) -> Result<Vec<u8>, String> {
            let sk_arr: [u8; 32] = seed
                .try_into()
                .map_err(|_| "Invalid seed length".to_string())?;
            let dk = DecapsulationKey::from(sk_arr);
            let ss = dk
                .decapsulate_slice(ct)
                .map_err(|_| {
                    "Invalid ciphertext length".to_string()
                })?;
            let ss_s: &[u8] = &ss;
            Ok(ss_s.to_vec())
        }

        fn seed_len() -> usize {
            32
        }

        fn ek_len() -> usize {
            1216
        }
    }
}

define_kem_variant!(
    MlKem512Dk,
    "PQCrypto\\MLKem512\\DecapsulationKey",
    MlKem512Ek,
    "PQCrypto\\MLKem512\\EncapsulationKey",
    MlKem512Algo,
    "PQCrypto\\MLKem512",
    mlkem_ops::MlKem512Ops
);

define_kem_variant!(
    MlKem768Dk,
    "PQCrypto\\MLKem768\\DecapsulationKey",
    MlKem768Ek,
    "PQCrypto\\MLKem768\\EncapsulationKey",
    MlKem768Algo,
    "PQCrypto\\MLKem768",
    mlkem_ops::MlKem768Ops
);

define_kem_variant!(
    MlKem1024Dk,
    "PQCrypto\\MLKem1024\\DecapsulationKey",
    MlKem1024Ek,
    "PQCrypto\\MLKem1024\\EncapsulationKey",
    MlKem1024Algo,
    "PQCrypto\\MLKem1024",
    mlkem_ops::MlKem1024Ops
);

define_kem_variant!(
    XWingDk,
    "PQCrypto\\XWing\\DecapsulationKey",
    XWingEk,
    "PQCrypto\\XWing\\EncapsulationKey",
    XWingAlgo,
    "PQCrypto\\XWing",
    xwing_ops::XWingOps
);

#[cfg(test)]
mod tests {
    use super::mlkem_ops::{MlKem512Ops, MlKem768Ops, MlKem1024Ops};
    use super::xwing_ops::XWingOps;
    use super::KemOps;

    fn run_kem_test<T: KemOps>(seed_len: usize, ek_len: usize) {
        let (seed, ek) = T::generate();
        assert_eq!(seed.len(), seed_len);
        assert_eq!(ek.len(), ek_len);

        let (ss, ct) = T::encapsulate(&ek).unwrap();
        let rss = T::decapsulate(&seed, &ct).unwrap();
        assert_eq!(ss, rss);

        assert!(T::decapsulate(b"short", &ct).is_err());
        assert!(T::decapsulate(&seed, b"bad").is_err());
    }

    #[test]
    fn mlkem512() { run_kem_test::<MlKem512Ops>(64, 800); }

    #[test]
    fn mlkem768() { run_kem_test::<MlKem768Ops>(64, 1184); }

    #[test]
    fn mlkem1024() { run_kem_test::<MlKem1024Ops>(64, 1568); }

    #[test]
    fn xwing() { run_kem_test::<XWingOps>(32, 1216); }
}
