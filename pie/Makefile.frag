$(builddir)/pqcrypto.lo: $(srcdir)/../target/release/libpqcrypto.so

$(srcdir)/../target/release/libpqcrypto.so:
	@echo "Building pqcrypto via Cargo..."
	@cd $(srcdir)/.. && cargo build --release

LDFLAGS += -L$(srcdir)/../target/release
LIBS += -lpqcrypto

modules/pqcrypto.so: $(srcdir)/../target/release/libpqcrypto.so
	@echo "Copying Cargo build..."
	@mkdir -p modules
	@cp $(srcdir)/../target/release/libpqcrypto.so modules/pqcrypto.so 2>/dev/null || cp $(srcdir)/../target/release/libpqcrypto.dylib modules/pqcrypto.so

all: modules/pqcrypto.so
