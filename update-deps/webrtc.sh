#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-v4.2.11}"
DST="$REPO/webrtc"
OLD_WEBRTC="github.com/pion/webrtc/v4"
OLD_DTLS="github.com/pion/dtls/v3"
NEW_WEBRTC="github.com/kulikov0/headlessclient/webrtc"
NEW_DTLS="github.com/kulikov0/headlessclient/internal/dtls"

go -C "$REPO" mod download "$OLD_WEBRTC@$VERSION"
SRC="$(go env GOMODCACHE)/$OLD_WEBRTC@$VERSION"
if [ ! -d "$SRC" ]; then
  echo "webrtc $VERSION not in module cache at $SRC" >&2
  exit 1
fi

rm -rf "$DST"
cp -R "$SRC" "$DST"
chmod -R u+w "$DST"
rm -rf "$DST/.git" "$DST/.github" "$DST/go.mod" "$DST/go.sum"
find "$DST" -type d -name '.git' -exec rm -rf {} + 2>/dev/null || true
find "$DST" -name '*_test.go' -delete
find "$DST" -type d \( -name testdata -o -name examples -o -name e2e \) -exec rm -rf {} + 2>/dev/null || true
rm -f "$DST/README.md" "$DST/codecov.yml" "$DST/renovate.json"

grep -rl "$OLD_WEBRTC\|$OLD_DTLS" "$DST" --include='*.go' | while read -r f; do
  perl -pi -e "s#\\Q$OLD_WEBRTC\\E#$NEW_WEBRTC#g; s#\\Q$OLD_DTLS\\E#$NEW_DTLS#g" "$f"
done

if grep -rq "$OLD_WEBRTC\|$OLD_DTLS" "$DST" --include='*.go'; then
  echo "residual upstream references remain" >&2
  exit 1
fi

go -C "$REPO" build ./webrtc/...
echo "webrtc regenerated from $OLD_WEBRTC@$VERSION"
