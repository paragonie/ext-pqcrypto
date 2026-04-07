<?php
declare(strict_types=1);
namespace PQCrypto\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MLDSATest extends TestCase
{
    /** @return array<string, array{string, int, int, int}> */
    public static function variantProvider(): array
    {
        return [
            'MLDSA44' => ['PQCrypto\\MLDSA44', 32, 1312, 2420],
            'MLDSA65' => ['PQCrypto\\MLDSA65', 32, 1952, 3309],
            'MLDSA87' => ['PQCrypto\\MLDSA87', 32, 2592, 4627],
        ];
    }

    #[DataProvider('variantProvider')]
    public function testKeygenSizes(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        [$sk, $vk] = $class::generateKeypair();
        $this->assertSame($seedLen, strlen($sk->bytes()));
        $this->assertSame($vkLen, strlen($vk->bytes()));
    }

    #[DataProvider('variantProvider')]
    public function testSignVerifyRoundTrip(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        [$sk, $vk] = $class::generateKeypair();
        $sig = $sk->sign('test message');
        $this->assertSame($sigLen, strlen($sig));
        $this->assertTrue($vk->verify($sig, 'test message'));
        $this->assertFalse($vk->verify($sig, 'wrong message'));
    }

    #[DataProvider('variantProvider')]
    public function testSigningKeyFromBytesRoundTrip(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        [$sk, $vk] = $class::generateKeypair();
        $skClass = $class . '\\SigningKey';
        $restored = $skClass::fromBytes($sk->bytes());
        $sig = $restored->sign('round-trip test');
        $this->assertTrue($vk->verify($sig, 'round-trip test'));
    }

    #[DataProvider('variantProvider')]
    public function testVerifyingKeyFromBytesRoundTrip(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        [$sk, $vk] = $class::generateKeypair();
        $vkClass = $class . '\\VerifyingKey';
        $restored = $vkClass::fromBytes($vk->bytes());
        $sig = $sk->sign('vk round-trip');
        $this->assertTrue($restored->verify($sig, 'vk round-trip'));
    }

    #[DataProvider('variantProvider')]
    public function testSigningKeyRejectsWrongLength(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        $skClass = $class . '\\SigningKey';
        $this->expectException(\Exception::class);
        $skClass::fromBytes('short');
    }

    #[DataProvider('variantProvider')]
    public function testVerifyingKeyRejectsWrongLength(
        string $class,
        int $seedLen,
        int $vkLen,
        int $sigLen
    ): void {
        $vkClass = $class . '\\VerifyingKey';
        $this->expectException(\Exception::class);
        $vkClass::fromBytes('short');
    }
}
