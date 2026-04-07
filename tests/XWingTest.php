<?php
declare(strict_types=1);
namespace PQCrypto\Tests;

use PHPUnit\Framework\TestCase;
use PQCrypto\XWing;

final class XWingTest extends TestCase
{
    public function testKeygenSizes(): void
    {
        [$sk, $pk] = XWing::generateKeypair();
        $this->assertSame(32, strlen($sk->bytes()));
        $this->assertSame(1216, strlen($pk->bytes()));
    }

    public function testEncapsulateDecapsulateRoundTrip(): void
    {
        [$sk, $pk] = XWing::generateKeypair();
        [$ss, $ct] = $pk->encapsulate();
        $this->assertSame(32, strlen($ss));
        $this->assertSame(1120, strlen($ct));
        $rss = $sk->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    public function testDecapsulationKeyFromBytesRoundTrip(): void
    {
        [$sk, $pk] = XWing::generateKeypair();
        $restored = XWing\DecapsulationKey::fromBytes($sk->bytes());
        [$ss, $ct] = $pk->encapsulate();
        $rss = $restored->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    public function testEncapsulationKeyFromBytesRoundTrip(): void
    {
        [$sk, $pk] = XWing::generateKeypair();
        $restored = XWing\EncapsulationKey::fromBytes($pk->bytes());
        [$ss, $ct] = $restored->encapsulate();
        $rss = $sk->decapsulate($ct);
        $this->assertTrue(hash_equals($rss, $ss));
    }

    public function testRejectsWrongSeedLength(): void
    {
        $this->expectException(\Exception::class);
        XWing\DecapsulationKey::fromBytes('short');
    }

    public function testRejectsWrongCiphertextLength(): void
    {
        [$sk, $_] = XWing::generateKeypair();
        $this->expectException(\Exception::class);
        $sk->decapsulate('wrong');
    }
}
