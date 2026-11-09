#!/usr/bin/env bash
# Build the release artefacts locally:
#   dist/fritzrecon-<version>-linux-<arch>.tar.gz
#   dist/fritzrecon_<version>-1_<debarch>.deb     (when nfpm is available)
#   dist/fritzrecon-<version>-1.<rpmarch>.rpm     (when nfpm is available)
#   dist/SHA256SUMS
#
# Usage: packaging/build-local.sh [--no-nfpm]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
[ -n "$VERSION" ] || { echo "cannot read the version from Cargo.toml" >&2; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) HOST_ARCH=x86_64; TAR_ARCH=amd64; DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
    aarch64|arm64) HOST_ARCH=aarch64; TAR_ARCH=arm64; DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

WITH_NFPM=1
[ "${1:-}" = "--no-nfpm" ] && WITH_NFPM=0

# Prefer a static musl build. It is what the release CI publishes; the glibc
# fallback only works on systems at least as recent as the build host.
TARGET="$HOST_ARCH-unknown-linux-musl"
if command -v musl-gcc >/dev/null 2>&1 \
   && rustc --print target-list | grep -qx "$TARGET" \
   && rustc --print sysroot | grep -q "rustlib/$TARGET"; then
    cargo build --release --locked --target "$TARGET"
    BIN="target/$TARGET/release/fritzrecon"
else
    echo "warning: musl target unavailable; building a glibc binary" >&2
    echo "warning: install musl-tools and 'rustup target add $TARGET' for a portable build" >&2
    cargo build --release --locked
    BIN="target/release/fritzrecon"
fi

rm -rf dist stage pkgroot
mkdir -p dist "stage/fritzrecon-$VERSION-linux-$TAR_ARCH"
cp "$BIN" "stage/fritzrecon-$VERSION-linux-$TAR_ARCH/"
cp LICENSE README.md CHANGELOG.md config.example.toml \
   "stage/fritzrecon-$VERSION-linux-$TAR_ARCH/"
cp -r docs "stage/fritzrecon-$VERSION-linux-$TAR_ARCH/"
tar -C stage -czf "dist/fritzrecon-$VERSION-linux-$TAR_ARCH.tar.gz" \
    "fritzrecon-$VERSION-linux-$TAR_ARCH"

if [ "$WITH_NFPM" = 1 ] && command -v nfpm >/dev/null 2>&1; then
    mkdir -p pkgroot
    cp "$BIN" pkgroot/fritzrecon
    cp LICENSE README.md CHANGELOG.md config.example.toml pkgroot/
    cp -r docs pkgroot/docs
    (cd pkgroot && PKG_VERSION="$VERSION" PKG_ARCH="$DEB_ARCH" \
        nfpm package -f "$ROOT/packaging/nfpm.yaml" -p deb -t "$ROOT/dist/")
    (cd pkgroot && PKG_VERSION="$VERSION" PKG_ARCH="$RPM_ARCH" \
        nfpm package -f "$ROOT/packaging/nfpm.yaml" -p rpm -t "$ROOT/dist/")
else
    echo "nfpm not found (or --no-nfpm): skipping .deb/.rpm" >&2
fi

(cd dist && sha256sum ./* > SHA256SUMS)
echo "artefacts in $ROOT/dist:"
ls -lh dist
