# Changelog

All notable changes to fritzrecon are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.6] - 2026-11-10

### Changed

- Publish to crates.io automatically from the GitHub Actions release
  workflow, with a dedicated `CARGO_REGISTRY_TOKEN` secret and an idempotent
  existence check.
- README: crates.io badge and `cargo install fritzrecon` instructions.

## [0.1.5] - 2026-11-09

### Changed

- Prepare the crates.io package: exclude CI, container and packaging files
  from the crate, and use absolute README links so the screenshots render on
  crates.io.
- Publish the crate as `fritzrecon` on crates.io.

## [0.1.4] - 2026-11-09

### Fixed

- Build GitLab release packages on Ubuntu 24.04 instead of Debian 12: its
  `musl-gcc` produces a working static-pie binary.

## [0.1.3] - 2026-11-09

### Fixed

- Force static musl binaries with `+crt-static` and print the `file(1)`
  result before the static-link check, so GitLab packaging cannot publish a
  dynamically linked binary.

## [0.1.2] - 2026-11-09

### Fixed

- GitLab release packaging: install `file`, used to verify that the musl
  binary is statically linked.

## [0.1.1] - 2026-11-09

### Added

- Automated release packaging: static amd64/arm64 tarballs, `.deb`, `.rpm`,
  `SHA256SUMS` and a `ghcr.io/zx97/fritzrecon` container image.
- Anonymised screenshots in the README.
- `make dist` and `packaging/build-local.sh` for local artefacts.

### Changed

- Release binaries are built with the musl target and have no runtime library
  dependencies.
- The release profile now strips symbols, enables thin LTO and uses one codegen
  unit.

## [0.1.0] - 2026-11-09

### Added

- Reconciliation of the FRITZ!Box REST device list, TR-064 Hosts, FRITZ!Box
  A/PTR DNS records, Pi-hole v6 local DNS and network tables, and the local
  ARP table.
- Ratatui TUI with sorting (`F5`/`F6`), filters, details, conflict
  explanations, English/French UI, and `Home`/`End` navigation.
- Selective device deletion and global AVM `cleanup_landevices`, both gated by
  a typed confirmation and a JSON backup.
- Scriptable `--json`, `--delete`, `--cleanup-inactive` and `--dry-run` modes.
- Optional Pi-hole v6 authentication (`PIHOLE_PASS`, `password_file`, TOTP).
- Configurable IP zones (`[scan.zones]`) and FRITZ!Box factory defaults.
- Embedded documentation and licence: `--documentation`, `--licence`.
- Automated release packaging: static amd64/arm64 tarballs, `.deb`, `.rpm`,
  `SHA256SUMS` and a `ghcr.io/zx97/fritzrecon` container image.
- Anonymised screenshots in the README.
- GNU Affero General Public License v3.0 or later.

[0.1.6]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.6
[0.1.5]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.5
[0.1.4]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.4
[0.1.3]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.3
[0.1.2]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.2
[0.1.1]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.1
[0.1.0]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.0
