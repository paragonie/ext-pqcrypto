.PHONY: build install clean test lint

EXT_PATH := $(shell pwd)/target/release/libpqcrypto.dylib
PHP_EXTENSION_DIR := $(shell php-config --extension-dir)
PHP_INI_DIR := $(shell php-config --ini-dir 2>/dev/null || echo "/etc/php.d")

build:
	cargo build --release

lint: build
	cargo clippy --release -- -D warnings
	php -l stubs/PQCrypto.php

test: build
	php -d "extension=$(EXT_PATH)" vendor/bin/phpunit

install: build
	cp target/release/libpqcrypto.dylib "$(PHP_EXTENSION_DIR)/pqcrypto.so" 2>/dev/null || \
	cp target/release/libpqcrypto.so "$(PHP_EXTENSION_DIR)/pqcrypto.so"
	@echo "Extension installed to $(PHP_EXTENSION_DIR)/pqcrypto.so"
	@echo "Add 'extension=pqcrypto' to your php.ini or:"
	@echo "  echo 'extension=pqcrypto' > $(PHP_INI_DIR)/50-pqcrypto.ini"

clean:
	cargo clean
