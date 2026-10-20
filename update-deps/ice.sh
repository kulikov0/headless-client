#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UD="$REPO/update-deps"
VERSION="${1:-v4.2.2}"
DST="$REPO/internal/ice"
OLD_ICE="github.com/pion/ice/v4"
NEW_ICE="github.com/kulikov0/headless-client/internal/ice"

go -C "$REPO" mod download "$OLD_ICE@$VERSION"
SRC="$(go env GOMODCACHE)/$OLD_ICE@$VERSION"
if [ ! -d "$SRC" ]; then
  echo "ice $VERSION not in module cache at $SRC" >&2
  exit 1
fi

. "$UD/common.sh"

rm -rf "$DST"
mkdir -p "$(dirname "$DST")"
cp -R "$SRC" "$DST"
chmod -R u+w "$DST"
rm -rf "$DST/.git" "$DST/.github" "$DST/go.mod" "$DST/go.sum"
find "$DST" -type d -name '.git' -exec rm -rf {} + 2>/dev/null || true
find "$DST" -name '*_test.go' -delete
find "$DST" -type d \( -name testdata -o -name examples -o -name e2e \) -exec rm -rf {} + 2>/dev/null || true
rm -f "$DST/codecov.yml" "$DST/renovate.json" "$DST/.gitignore" "$DST/.golangci.yml" \
  "$DST/.goreleaser.yml" "$DST/.editorconfig"
find "$DST" -name 'README.md' -delete

grep -rl "$OLD_ICE" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD_ICE\\E#$NEW_ICE#g" "$f"
done

apply_patch "$DST" "$UD/ice-keepalive-interval.patch"

if grep -rq "$OLD_ICE" "$DST" --include='*.go'; then
  echo "residual $OLD_ICE references remain" >&2
  exit 1
fi

gofmt -w "$DST"

go -C "$REPO" build ./internal/ice/...
echo "internal/ice regenerated from $OLD_ICE@$VERSION"
