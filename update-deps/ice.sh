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

apply_patch() {
  patch_file="$1"
  patch_name="$(basename "$patch_file")"
  if patch -p1 -d "$DST" -N --dry-run -s < "$patch_file" >/dev/null 2>&1; then
    patch -p1 -d "$DST" -N -s < "$patch_file"
    echo "applied $patch_name"
  elif patch -p1 -d "$DST" -R --dry-run -s < "$patch_file" >/dev/null 2>&1; then
    echo "skipped $patch_name, already present in the source"
  else
    echo "cannot apply $patch_name" >&2
    exit 1
  fi
}

rm -rf "$DST"
mkdir -p "$(dirname "$DST")"
cp -R "$SRC" "$DST"
chmod -R u+w "$DST"
rm -rf "$DST/.git" "$DST/.github" "$DST/go.mod" "$DST/go.sum"
find "$DST" -type d -name '.git' -exec rm -rf {} + 2>/dev/null || true
find "$DST" -name '*_test.go' -delete
find "$DST" -type d \( -name testdata -o -name examples -o -name e2e \) -exec rm -rf {} + 2>/dev/null || true
rm -f "$DST/README.md" "$DST/codecov.yml" "$DST/renovate.json"

grep -rl "$OLD_ICE" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD_ICE\\E#$NEW_ICE#g" "$f"
done

apply_patch "$UD/ice-keepalive-interval.patch"

if grep -rq "$OLD_ICE" "$DST" --include='*.go'; then
  echo "residual $OLD_ICE references remain" >&2
  exit 1
fi

gofmt -w "$DST"

go -C "$REPO" build ./internal/ice/...
echo "internal/ice regenerated from $OLD_ICE@$VERSION"
