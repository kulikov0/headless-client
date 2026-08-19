#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$REPO/../dtls}"
DST="$REPO/internal/dtls"
UD="$REPO/update-deps"
OLD="github.com/pion/dtls/v3"
NEW="github.com/kulikov0/headlessclient/internal/dtls"

if [ ! -d "$SRC" ]; then
  echo "dtls fork not found at $SRC" >&2
  echo "usage: $0 [path-to-dtls-fork]" >&2
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
rm -rf "$DST/.git" "$DST/go.mod" "$DST/go.sum"
find "$DST" -name '*_test.go' -delete
find "$DST" -type d \( -name testdata -o -name examples -o -name e2e \) -exec rm -rf {} + 2>/dev/null || true
rm -f "$DST/README.md" "$DST/codecov.yml" "$DST/renovate.json"

grep -rl "$OLD" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD\\E#$NEW#g" "$f"
done

cp "$UD"/_dtls-files/*.go "$DST/"

apply_patch "$UD/dtls-default-version.patch"
apply_patch "$UD/dtls-dualstack-server-prime.patch"

if grep -rq "$OLD" "$DST" --include='*.go'; then
  echo "residual $OLD references remain" >&2
  exit 1
fi

go -C "$REPO" build ./internal/dtls/...
echo "internal/dtls regenerated from $SRC"
