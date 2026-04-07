<?php
declare(strict_types=1);
namespace PQCrypto\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MLKemTest extends TestCase
{
    /** @return array<string, array{string, int, int, int, int}> */
    public static function variantProvider(): array
    {
        return [
            'MLKem512'  => ['PQCrypto\\MLKem512',  64, 800,  768,  32],
            'MLKem768'  => ['PQCrypto\\MLKem768',  64, 1184, 1088, 32],
            'MLKem1024' => ['PQCrypto\\MLKem1024', 64, 1568, 1568, 32],
        ];
    }

    #[DataProvider('variantProvider')]
    public function testKeygenSizes(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        [$sk, $pk] = $class::generateKeypair();
        $this->assertSame($seedLen, strlen($sk->bytes()));
        $this->assertSame($ekLen, strlen($pk->bytes()));
    }

    #[DataProvider('variantProvider')]
    public function testEncapsulateDecapsulateRoundTrip(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        [$sk, $pk] = $class::generateKeypair();
        [$ss, $ct] = $pk->encapsulate();
        $this->assertSame($ssLen, strlen($ss));
        $this->assertSame($ctLen, strlen($ct));
        $rss = $sk->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    #[DataProvider('variantProvider')]
    public function testDecapsulationKeyFromBytesRoundTrip(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        [$sk, $pk] = $class::generateKeypair();
        $dkClass = $class . '\\DecapsulationKey';
        $restored = $dkClass::fromBytes($sk->bytes());
        [$ss, $ct] = $pk->encapsulate();
        $rss = $restored->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    #[DataProvider('variantProvider')]
    public function testEncapsulationKeyFromBytesRoundTrip(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        [$sk, $pk] = $class::generateKeypair();
        $ekClass = $class . '\\EncapsulationKey';
        $restored = $ekClass::fromBytes($pk->bytes());
        [$ss, $ct] = $restored->encapsulate();
        $rss = $sk->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    #[DataProvider('variantProvider')]
    public function testDecapsulationKeyRejectsWrongLength(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        $dkClass = $class . '\\DecapsulationKey';
        $this->expectException(\Exception::class);
        $dkClass::fromBytes('too short');
    }

    #[DataProvider('variantProvider')]
    public function testEncapsulationKeyRejectsWrongLength(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        $ekClass = $class . '\\EncapsulationKey';
        $this->expectException(\Exception::class);
        $ekClass::fromBytes('too short');
    }

    #[DataProvider('variantProvider')]
    public function testDecapsulateRejectsWrongCiphertext(
        string $class,
        int $seedLen,
        int $ekLen,
        int $ctLen,
        int $ssLen
    ): void {
        [$sk, $_] = $class::generateKeypair();
        $this->expectException(\Exception::class);
        $sk->decapsulate('wrong length ciphertext');
    }
}
