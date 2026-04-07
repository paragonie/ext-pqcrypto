#![allow(non_snake_case)]
#![cfg_attr(windows, feature(abi_vectorcall))]

use ext_php_rs::prelude::*;

mod kem;
mod sig;

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
    	.name("pqcrypto")
        // ML-KEM
        .class::<kem::MlKem512Dk>()
        .class::<kem::MlKem512Ek>()
        .class::<kem::MlKem512Algo>()
        .class::<kem::MlKem768Dk>()
        .class::<kem::MlKem768Ek>()
        .class::<kem::MlKem768Algo>()
        .class::<kem::MlKem1024Dk>()
        .class::<kem::MlKem1024Ek>()
        .class::<kem::MlKem1024Algo>()
        // X-Wing
        .class::<kem::XWingDk>()
        .class::<kem::XWingEk>()
        .class::<kem::XWingAlgo>()
        // ML-DSA
        .class::<sig::MlDsa44Sk>()
        .class::<sig::MlDsa44Vk>()
        .class::<sig::MlDsa44Algo>()
        .class::<sig::MlDsa65Sk>()
        .class::<sig::MlDsa65Vk>()
        .class::<sig::MlDsa65Algo>()
        .class::<sig::MlDsa87Sk>()
        .class::<sig::MlDsa87Vk>()
        .class::<sig::MlDsa87Algo>()
        // SLH-DSA
        .class::<sig::SlhDsaSigningKey>()
        .class::<sig::SlhDsaVerifyingKey>()
        .class::<sig::SlhDsa>()
}
