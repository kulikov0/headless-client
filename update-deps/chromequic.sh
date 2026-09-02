#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-v1.2.28}"
QPACK_VERSION="${2:-v0.6.3}"
UD="$REPO/update-deps"
DST="$REPO/quic"
MOD="github.com/kulikov0/headless-client/quic"

. "$UD/common.sh"

go -C "$REPO" mod download "github.com/sardanioss/quic-go@$VERSION"
go -C "$REPO" mod download "github.com/sardanioss/qpack@$QPACK_VERSION"
SRC="$(go env GOMODCACHE)/github.com/sardanioss/quic-go@$VERSION"
QPACK_SRC="$(go env GOMODCACHE)/github.com/sardanioss/qpack@$QPACK_VERSION"
for dir in "$SRC" "$QPACK_SRC"; do
  if [ ! -d "$dir" ]; then
    echo "missing source at $dir" >&2
    exit 1
  fi
done

rm -rf "$DST"
mkdir -p "$DST"
cp -R "$SRC/." "$DST/"
mkdir -p "$DST/qpack"
cp "$QPACK_SRC"/*.go "$DST/qpack/"
cp "$QPACK_SRC/LICENSE.md" "$DST/qpack/LICENSE.md"
chmod -R u+w "$DST"

find "$DST" -depth -name '.git' -exec rm -rf {} +
rm -rf "$DST/.github" "$DST/.githooks" "$DST/.clusterfuzzlite" "$DST/assets" \
  "$DST/example" "$DST/interop" "$DST/fuzzing" "$DST/integrationtests" \
  "$DST/testutils" "$DST/metrics" "$DST/tools" "$DST/internal/mocks"
rm -f "$DST/go.mod" "$DST/go.sum" "$DST/SECURITY.md" "$DST/codecov.yml" \
  "$DST/oss-fuzz.sh" "$DST/mockgen.go" "$DST/.gitignore" "$DST/.golangci.yml"
find "$DST" -depth -type d -name 'testdata' -exec rm -rf {} +
find "$DST" -name 'README.md' -delete
find "$DST" -name '*_test.go' -delete
find "$DST" -name 'mock_*.go' -delete
find "$DST" -type d -empty -delete

grep -rl 'github.com/sardanioss/' "$DST" --include='*.go' | while read -r file; do
  perl -pi -e "
    s#github\\.com/sardanioss/quic-go#$MOD#g;
    s#github\\.com/sardanioss/qpack#$MOD/qpack#g;
    s#github\\.com/sardanioss/utls#github.com/refraction-networking/utls#g;
    s#github\\.com/sardanioss/http/httptrace#net/http/httptrace#g;
    s#\\bhttp \"github\\.com/sardanioss/http\"#\"net/http\"#g;
    s#\"github\\.com/sardanioss/http\"#\"net/http\"#g;
  " "$file"
done

grep -rl 'http\.\(P\)\?HeaderOrderKey' "$DST/http3" --include='*.go' | while read -r file; do
  perl -pi -e 's#\bhttp\.PHeaderOrderKey\b#pHeaderOrderKey#g; s#\bhttp\.HeaderOrderKey\b#headerOrderKey#g;' "$file"
done

cp "$UD/_chromequic-files/header_order_keys.go" "$DST/http3/header_order_keys.go"

if grep -rq 'github.com/sardanioss/' "$DST" --include='*.go'; then
  echo "residual github.com/sardanioss references remain" >&2
  grep -rn 'github.com/sardanioss/' "$DST" --include='*.go' | head >&2
  exit 1
fi

gofmt -w "$DST"

cp "$UD/_chromequic-files/tls_state.go" "$DST/http3/tls_state.go"
apply_patch "$DST" "$UD/chromequic-refraction-utls.patch"
apply_patch "$DST" "$UD/chromequic-preset-transport-params.patch"

go -C "$REPO" build ./quic/...
echo "quic regenerated from github.com/sardanioss/quic-go@$VERSION"
