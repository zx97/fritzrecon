.PHONY: build release clean doc licence check

build:
	cargo build

release:
	cargo build --release
	strip target/release/fritzrecon

# Print the documentation and licence embedded in the binary.
doc:
	@cargo run --quiet -- --documentation

licence:
	@cargo run --quiet -- --licence

# Run the tests, build a release binary and verify the embedded texts.
check:
	cargo test
	$(MAKE) release
	@target/release/fritzrecon --licence >/dev/null
	@target/release/fritzrecon --documentation >/dev/null
	@echo "check: tests, release build and embedded documentation OK"

clean:
	cargo clean
