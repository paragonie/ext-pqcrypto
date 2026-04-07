<?php
declare(strict_types=1);
namespace PQCrypto\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PQCrypto\SLHDSA;

final class SLHDSATest extends TestCase
{
    /** @return array<string, array{string, string, int, int}> */
    public static function parameterSetProvider(): array
    {
        return [
            'shake128-fast'  => ['shake128', 'fast',  64,  32],
            'shake128-small' => ['shake128', 'small', 64,  32],
            'shake192-fast'  => ['shake192', 'fast',  96,  48],
            'shake192-small' => ['shake192', 'small', 96,  48],
            'shake256-fast'  => ['shake256', 'fast',  128, 64],
            'shake256-small' => ['shake256', 'small', 128, 64],
            'sha2-128-fast'  => ['sha2-128', 'fast',  64,  32],
            'sha2-128-small' => ['sha2-128', 'small', 64,  32],
            'sha2-192-fast'  => ['sha2-192', 'fast',  96,  48],
            'sha2-192-small' => ['sha2-192', 'small', 96,  48],
            'sha2-256-fast'  => ['sha2-256', 'fast',  128, 64],
            'sha2-256-small' => ['sha2-256', 'small', 128, 64],
        ];
    }

    #[DataProvider('parameterSetProvider')]
    public function testSignVerifyRoundTrip(
        string $hash,
        string $speed,
        int $skLen,
        int $vkLen
    ): void {
        $slh = new SLHDSA($hash, $speed);
        [$sk, $vk] = $slh->generateKeypair();
        $this->assertSame($skLen, strlen($sk->bytes()));
        $this->assertSame($vkLen, strlen($vk->bytes()));

        $sig = $sk->sign('slh-dsa test');
        $this->assertGreaterThan(0, strlen($sig));
        $this->assertTrue($vk->verify($sig, 'slh-dsa test'));
        $this->assertFalse($vk->verify($sig, 'wrong'));
    }

    #[DataProvider('parameterSetProvider')]
    public function testImportRoundTrip(
        string $hash,
        string $speed,
        int $skLen,
        int $vkLen
    ): void {
        $slh = new SLHDSA($hash, $speed);
        [$sk, $vk] = $slh->generateKeypair();

        $skRestored = $slh->importSigningKey($sk->bytes());
        $vkRestored = $slh->importVerifyingKey($vk->bytes());

        $sig = $skRestored->sign('import test');
        $this->assertTrue(
            $vkRestored->verify($sig, 'import test')
        );
    }

    public function testRejectsInvalidHash(): void
    {
        $this->expectException(\Exception::class);
        new SLHDSA('invalid', 'fast');
    }

    public function testRejectsInvalidSpeed(): void
    {
        $this->expectException(\Exception::class);
        new SLHDSA('shake128', 'invalid');
    }

    public function testImportSigningKeyRejectsWrongLength(): void
    {
        $slh = new SLHDSA('shake128', 'fast');
        $this->expectException(\Exception::class);
        $slh->importSigningKey('short');
    }

    public function testImportVerifyingKeyRejectsWrongLength(): void
    {
        $slh = new SLHDSA('shake128', 'fast');
        $this->expectException(\Exception::class);
        $slh->importVerifyingKey('short');
    }
}
