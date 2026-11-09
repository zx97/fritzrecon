.PHONY: build release clean doc licence check dist

build:
	cargo build

release:
	cargo build --release

# Print the documentation and licence embedded in the binary.
doc:
	@cargo run --quiet -- --documentation

licence:
	@cargo run --quiet -- --licence

# Build the release artefacts (tarball, .deb/.rpm when nfpm is installed).
dist:
	packaging/build-local.sh

# Run the tests, build a release binary and verify the embedded texts.
check:
	cargo test
	$(MAKE) release
	@target/release/fritzrecon --licence >/dev/null
	@target/release/fritzrecon --documentation >/dev/null
	@echo "check: tests, release build and embedded documentation OK"

clean:
	cargo clean
	rm -rf dist stage pkgroot
