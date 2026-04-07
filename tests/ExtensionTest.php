<?php
declare(strict_types=1);
namespace PQCrypto\Tests;

use PHPUnit\Framework\TestCase;

final class ExtensionTest extends TestCase
{
    public function testExtensionLoaded(): void
    {
        $this->assertTrue(extension_loaded('pqcrypto'));
    }
}
