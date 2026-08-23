#!/bin/bash
set -euo pipefail

usage() {
  echo "usage: chromium.sh --display DISPLAY --url URL [--keep-profile] [-- chromium flags...]" >&2
  exit 1
}

display=
url=
keep=0
profile=/stand/profiles/browser

while [ $# -gt 0 ]; do
  case $1 in
    --display) display=$2; shift 2 ;;
    --url) url=$2; shift 2 ;;
    --keep-profile) keep=1; shift ;;
    --) shift; break ;;
    *) usage ;;
  esac
done

[ -n "$display" ] && [ -n "$url" ] || usage

if [ "$keep" -eq 0 ]; then
  rm -rf "$profile"
fi
mkdir -p "$profile"

exec env DISPLAY="$display" chromium \
  --no-sandbox --test-type --disable-gpu --disable-dev-shm-usage --disable-infobars \
  --no-first-run --no-default-browser-check --disable-search-engine-choice-screen \
  --disable-background-networking \
  --disable-component-update \
  --disable-domain-reliability \
  --disable-client-side-phishing-detection \
  --disable-breakpad \
  --disable-sync \
  --allow-browser-signin=false \
  --safebrowsing-disable-auto-update \
  --metrics-recording-only \
  --no-pings \
  --no-service-autorun \
  --disable-features=OptimizationHints,OptimizationGuideModelDownloading,MediaRouter,Translate,AutofillServerCommunication,InterestFeedContentSuggestions,PrivacySandboxSettings4 \
  --user-data-dir="$profile" \
  "$@" \
  "$url"
