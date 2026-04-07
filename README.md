# ext-pqcrypto: Post-Quantum Cryptography for PHP

[![CI](https://github.com/paragonie/ext-pqcrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/ext-pqcrypto/actions/workflows/ci.yml)
[![Latest Stable Version](https://poser.pugx.org/paragonie/ext-pqcrypto/v/stable)](https://packagist.org/packages/paragonie/ext-pqcrypto)
[![License](https://poser.pugx.org/paragonie/ext-pqcrypto/license)](https://packagist.org/packages/paragonie/ext-pqcrypto)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/ext-pqcrypto.svg)](https://packagist.org/packages/paragonie/ext-pqcrypto)
[![crates.io](https://img.shields.io/crates/v/php-ext-pqcrypto.svg?logo=rust)](https://crates.io/crates/php-ext-pqcrypto)

A PHP extension (written in Rust) that exposes post-quantum cryptography algorithms from the 
[RustCrypto](https://github.com/RustCrypto) project.

Implements [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
(ML-DSA), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA), and [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
(hybrid X25519 + ML-KEM-768).

## Requirements

* PHP >= 8.1
* Rust toolchain (rustc >= 1.85, **nightly**)
* `php-config` in PATH (for ext-php-rs build)

## Building

```shell
make build   # cargo build --release
make test    # run PHP test suite
make install # copy to PHP extension dir
```

After installing, add `extension=pqcrypto` to your `php.ini`, then run:

```php
var_dump(extension_loaded('pqcrypto')); // bool(true)
```

## Usage

### X-Wing (Hybrid KEM: X25519 + ML-KEM-768)

> [!TIP]
>
> X-Wing is the recommend hybrid post-quantum KEM.

```php
[$sk, $pk] = PQCrypto\XWing::generateKeypair();

[$sharedSecret, $ciphertext] = $pk->encapsulate();
$recipientSecret = $sk->decapsulate($ciphertext);

assert(hash_equals($recipientSecret, $sharedSecret));
```

### ML-KEM (Key Encapsulation)

> [!TIP]
>
> We do not recommend ML-KEM-512, but include it for completeness.
> ML-KEM-768 or ML-KEM-1024 should be used if X-Wing is not acceptable.

```php
// ML-KEM-768 (also: MLKem512, MLKem1024)
[$sk, $pk] = PQCrypto\MLKem768::generateKeypair();

[$sharedSecret, $ciphertext] = $pk->encapsulate();
$recipientSecret = $sk->decapsulate($ciphertext);

assert(hash_equals($recipientSecret, $sharedSecret));

// Serialize / restore
$skBytes = $sk->bytes();  // 64-byte seed
$sk2 = PQCrypto\MLKem768\DecapsulationKey::fromBytes($skBytes);
```

### ML-DSA (Digital Signatures)

> [!TIP]
>
> ML-DSA-44 is fine. The larger parameter sets should only be used if you specifically need them for compliance reasons
> (i.e., CNSA 2.0).

```php
// ML-DSA-44 (also: MLDSA65, MLDSA87)
[$signingKey, $verifyingKey] = PQCrypto\MLDSA44::generateKeypair();

$signature = $signingKey->sign('message');
$valid = $verifyingKey->verify($signature, 'message'); // true
$invalid = $verifyingKey->verify($signature, 'wrong');  // false

// Serialize / restore
$seed = $signingKey->bytes(); // 32-byte seed
$sk2 = PQCrypto\MLDSA44\SigningKey::fromBytes($seed);
```

### SLH-DSA (Stateless Hash-Based Signatures)

```php
// Parameters: hash function + speed
// Hash: 'shake128', 'shake192', 'shake256',
//       'sha2-128', 'sha2-192', 'sha2-256'
// Speed: 'fast' (larger sigs) or 'small' (smaller sigs)
$slh = new PQCrypto\SLHDSA('shake256', 'fast');

[$signingKey, $verifyingKey] = $slh->generateKeypair();

$signature = $signingKey->sign('message');
$valid = $verifyingKey->verify($signature, 'message');

// Import keys
$sk2 = $slh->importSigningKey($signingKey->bytes());
$vk2 = $slh->importVerifyingKey($verifyingKey->bytes());
```

## Key Sizes

### KEM

| Algorithm   | Seed  | Public Key | Ciphertext | Shared Secret |
|-------------|-------|------------|------------|---------------|
| ML-KEM-512  | 64    | 800        | 768        | 32            |
| ML-KEM-768  | 64    | 1184       | 1088       | 32            |
| ML-KEM-1024 | 64    | 1568       | 1568       | 32            |
| X-Wing      | 32    | 1216       | 1120       | 32            |

### Signatures

| Algorithm        | Seed | Public Key | Signature |
|------------------|------|------------|-----------|
| ML-DSA-44        | 32   | 1312       | 2420      |
| ML-DSA-65        | 32   | 1952       | 3309      |
| ML-DSA-87        | 32   | 2592       | 4627      |
| SLH-DSA-*-128s   | 64   | 32         | 7856      |
| SLH-DSA-*-128f   | 64   | 32         | 17088     |
| SLH-DSA-*-192s   | 96   | 48         | 16224     |
| SLH-DSA-*-192f   | 96   | 48         | 35664     |
| SLH-DSA-*-256s   | 128  | 64         | 29792     |
| SLH-DSA-*-256f   | 128  | 64         | 49856     |

All sizes above are measured in bytes. 

Secret keys are stored as seeds, never semi-expanded secrets. This is a 
[deliberate design choice](https://words.filippo.io/ml-kem-seeds/).
