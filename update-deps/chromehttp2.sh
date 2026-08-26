#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-v0.55.0}"
UD="$REPO/update-deps"
DST="$REPO/internal/chromehttp2"
MOD="github.com/kulikov0/headless-client/internal/chromehttp2"

go -C "$REPO" mod download "golang.org/x/net@$VERSION"
SRC="$(go env GOMODCACHE)/golang.org/x/net@$VERSION"
if [ ! -d "$SRC" ]; then
  echo "golang.org/x/net $VERSION not in module cache at $SRC" >&2
  exit 1
fi

copy_nontest() {
  local src="$1" dst="$2"
  mkdir -p "$dst"
  for f in "$src"/*.go; do
    case "$f" in *_test.go) continue;; esac
    cp "$f" "$dst/"
  done
}

rm -rf "$DST"
copy_nontest "$SRC/http2" "$DST"
copy_nontest "$SRC/internal/httpcommon" "$DST/internal/httpcommon"
copy_nontest "$SRC/internal/httpsfv" "$DST/internal/httpsfv"
cp "$SRC/LICENSE" "$DST/LICENSE"
cp "$SRC/PATENTS" "$DST/PATENTS"
chmod -R u+w "$DST"

grep -rl 'golang.org/x/net/internal/httpcommon\|golang.org/x/net/internal/httpsfv' "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#golang\\.org/x/net/internal/httpcommon#$MOD/internal/httpcommon#g; s#golang\\.org/x/net/internal/httpsfv#$MOD/internal/httpsfv#g" "$f"
done
perl -pi -e 's#^package http2 // import "golang.org/x/net/http2"#package http2#' "$DST/http2.go"

patch -p1 -d "$DST" < "$UD/chromehttp2-fingerprint.patch"

cp "$UD/_chromehttp2-tests/chrome_fingerprint_test.go" "$DST/chrome_fingerprint_test.go"
cp "$UD/_chromehttp2-tests/httpcommon/header_order_test.go" "$DST/internal/httpcommon/header_order_test.go"

if grep -rq 'golang.org/x/net/internal' "$DST" --include='*.go'; then
  echo "residual golang.org/x/net/internal references remain" >&2
  exit 1
fi

gofmt -w "$DST"

go -C "$REPO" build ./internal/chromehttp2/...
go -C "$REPO" test ./internal/chromehttp2/...
echo "internal/chromehttp2 regenerated from golang.org/x/net@$VERSION"
