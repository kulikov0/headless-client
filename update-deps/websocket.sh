#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UD="$REPO/update-deps"
VERSION="${1:-v1.5.3}"
DST="$REPO/websocket"
OLD="github.com/gorilla/websocket"
NEW="github.com/kulikov0/headlessclient/websocket"

go -C "$REPO" mod download "$OLD@$VERSION"
SRC="$(go env GOMODCACHE)/$OLD@$VERSION"
if [ ! -d "$SRC" ]; then
  echo "websocket $VERSION not in module cache at $SRC" >&2
  exit 1
fi

apply_patch() {
  patch_file="$1"
  if patch -d "$REPO" -p1 -N --dry-run --silent <"$patch_file" >/dev/null 2>&1; then
    patch -d "$REPO" -p1 -N --silent <"$patch_file"
    return
  fi
  if patch -d "$REPO" -p1 -R --dry-run --silent <"$patch_file" >/dev/null 2>&1; then
    echo "already applied, skipping $(basename "$patch_file")"
    return
  fi
  echo "cannot apply $(basename "$patch_file")" >&2
  exit 1
}

rm -rf "$DST"
cp -R "$SRC" "$DST"
chmod -R u+w "$DST"
rm -rf "$DST/.git" "$DST/.github" "$DST/.circleci" "$DST/go.mod" "$DST/go.sum"
find "$DST" -type d -name '.git' -exec rm -rf {} + 2>/dev/null || true
find "$DST" -name '*_test.go' -delete
find "$DST" -type d \( -name testdata -o -name examples -o -name e2e \) -exec rm -rf {} + 2>/dev/null || true
rm -f "$DST/README.md" "$DST/codecov.yml" "$DST/renovate.json" "$DST/.golangci.yml" "$DST/.gitignore"

grep -rl "$OLD" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD\\E#$NEW#g" "$f"
done || true

if grep -rq "$OLD" "$DST" --include='*.go'; then
  echo "residual upstream references remain" >&2
  exit 1
fi

apply_patch "$UD/websocket-chrome-handshake.patch"

go -C "$REPO" build ./websocket/...
echo "websocket regenerated from $OLD@$VERSION"
