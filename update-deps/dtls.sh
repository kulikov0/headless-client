#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DST="$REPO/internal/dtls"
UD="$REPO/update-deps"
UPSTREAM="https://github.com/pion/dtls"
COMMIT="16fcc8432011043c73b2cc3ae7e09f9429dd925d"
OLD="github.com/pion/dtls/v3"
NEW="github.com/kulikov0/headless-client/internal/dtls"

SRC="${1:-}"
SOURCE_LABEL="$UPSTREAM"

if [ -n "$SRC" ]; then
  SOURCE_LABEL="$SRC"
  if [ ! -d "$SRC" ]; then
    echo "dtls checkout not found at $SRC" >&2
    echo "usage: $0 [path-to-dtls-checkout]" >&2
    exit 1
  fi
  source_commit="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ "$source_commit" != "$COMMIT" ]; then
    echo "warning: $SRC is at $source_commit, pinned commit is $COMMIT" >&2
  fi
else
  SRC="$(mktemp -d)"
  trap 'rm -rf "$SRC"' EXIT
  git -C "$SRC" init --quiet
  if ! git -C "$SRC" fetch --quiet --depth 1 "$UPSTREAM" "$COMMIT" 2>/dev/null; then
    echo "cannot fetch $COMMIT from $UPSTREAM" >&2
    exit 1
  fi
  git -C "$SRC" checkout --quiet FETCH_HEAD
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
rm -f "$DST/README.md" "$DST/codecov.yml" "$DST/renovate.json"

grep -rl "$OLD" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD\\E#$NEW#g" "$f"
done

cp "$UD"/_dtls-files/*.go "$DST/"

apply_patch "$DST" "$UD/dtls-default-version.patch"
apply_patch "$DST" "$UD/dtls-dualstack-server-prime.patch"
apply_patch "$DST" "$UD/dtls-handshake-fragment-mtu.patch"
apply_patch "$DST" "$UD/dtls-serverhello13-hook.patch"

if grep -rq "$OLD" "$DST" --include='*.go'; then
  echo "residual $OLD references remain" >&2
  exit 1
fi

gofmt -w "$DST"

go -C "$REPO" build ./internal/dtls/...
echo "internal/dtls regenerated from $SOURCE_LABEL at $COMMIT"
