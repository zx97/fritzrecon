# Changelog

All notable changes to fritzrecon are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

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
- GNU Affero General Public License v3.0 or later.

[0.1.0]: https://github.com/zx97/fritzrecon/releases/tag/v0.1.0
