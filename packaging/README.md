# Release packaging

Every `v*` tag produces the following artefacts automatically:

| Artefact | Target | Built with |
|---|---|---|
| `fritzrecon-<version>-linux-amd64.tar.gz` | any Linux x86-64 | static musl binary |
| `fritzrecon-<version>-linux-arm64.tar.gz` | any Linux arm64 | static musl binary |
| `fritzrecon_<version>-1_amd64.deb` | Debian 12+, Ubuntu 22.04+ | the static binary, nfpm |
| `fritzrecon_<version>-1_arm64.deb` | Debian 12+, Ubuntu 22.04+ (arm64) | the static binary, nfpm |
| `fritzrecon-<version>-1.x86_64.rpm` | RHEL 9+, AlmaLinux 9+, Rocky 9+ | the static binary, nfpm |
| `fritzrecon-<version>-1.aarch64.rpm` | RHEL 9+, AlmaLinux 9+, Rocky 9+ (arm64) | the static binary, nfpm |
| `SHA256SUMS` | all | `sha256sum` |
| `ghcr.io/zx97/fritzrecon:<version>` | container, amd64 | `scratch` + static binary |

The binaries are built for the `*-unknown-linux-musl` targets, so the tarball
and the packages have **no runtime library dependencies** beyond the Linux
kernel. The container image is `FROM scratch` and contains only the static
binary (TLS roots are compiled in through `webpki-roots`).

## Local build

Requirements:

- `cargo`, `tar`, `sha256sum`;
- `nfpm` (<https://github.com/goreleaser/nfpm/releases>) in `PATH` for
  `.deb`/`.rpm`;
- `podman` only if you also build the container.

```bash
packaging/build-local.sh             # tarball + .deb + .rpm + SHA256SUMS
packaging/build-local.sh --no-nfpm   # tarball + SHA256SUMS only
```

The output is in `dist/`.

## CI

### GitHub Actions — `.github/workflows/release.yml`

- Triggered by a `v*` tag, or manually (`workflow_dispatch`, with an optional
  version; manual runs build and package but do not publish).
- Two native runners build the static musl binary:
  `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64).
- A packaging job runs `nfpm` for both architectures, writes `SHA256SUMS`,
  creates the GitHub release if it does not exist (notes from `CHANGELOG.md`)
  and uploads the assets.
- A container job builds and pushes `ghcr.io/zx97/fritzrecon` (version and
  `latest`).

### GitLab CI — `.gitlab-ci.yml`

- `package` (tag only): builds amd64, runs `make check`, produces the same
  tarball/.deb/.rpm and uploads them to the **Generic Package Registry**
  (`/packages/generic/fritzrecon/<version>/...`).
- `release` (tag only): creates a GitLab Release with links to the package
  registry assets.
- `container` (tag only): builds and pushes the amd64 image to the project
  container registry.

## Container usage

The container needs the host network to see the FRITZ!Box/Pi-hole and read the
host ARP table:

```bash
podman run --rm --network host \
  ghcr.io/zx97/fritzrecon:latest --config /config.toml --json
```

For the TUI, add `-it` and a TTY. Mount the configuration read-only:

```bash
podman run --rm -it --network host \
  -v "$HOME/.config/fritzrecon/config.toml:/config.toml:ro" \
  -v "$HOME/.config/fritzrecon/fritzrecon.pass:/fritzrecon.pass:ro" \
  ghcr.io/zx97/fritzrecon:latest --config /config.toml
```

The scratch image has no `HOME` or `/etc/passwd`, so pass `--config`
explicitly; otherwise the built-in defaults are used.

## Signing

`SHA256SUMS` is attached to every GitHub release. Detached GPG signatures are
not produced yet; add a signing step to the release job if the packages are
distributed through a repository.
