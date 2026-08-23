#!/bin/bash
set -euo pipefail

display=$1
vnc_port=$2
web_port=$3

for pid in $(pgrep -f '/stand/display.sh' || true); do
  [ "$pid" = "$$" ] || kill "$pid" 2>/dev/null || true
done
pkill -f "Xvnc $display" 2>/dev/null || true
pkill -f matchbox-window-manager 2>/dev/null || true
pkill -f "websockify.*$web_port" 2>/dev/null || true
sleep 0.3

Xvnc "$display" -geometry 1280x800 -depth 24 -SecurityTypes None \
  -rfbport "$vnc_port" -AlwaysShared -AcceptSetDesktopSize=1 -desktop browser \
  >/stand/xvnc.log 2>&1 &
sleep 1

DISPLAY="$display" matchbox-window-manager -use_titlebar no >/dev/null 2>&1 &

websockify --web=/usr/share/novnc "$web_port" "localhost:$vnc_port" >/stand/websockify.log 2>&1 &

while sleep 0.4; do
  geometry=$(DISPLAY="$display" xdotool getdisplaygeometry 2>/dev/null) || continue
  [ -n "$geometry" ] || continue
  window=$(DISPLAY="$display" xdotool search --onlyvisible --class '[Cc]hromium' 2>/dev/null | head -1) || continue
  if [ -n "$window" ]; then
    DISPLAY="$display" xdotool windowmove "$window" 0 0 \
      windowsize "$window" "${geometry% *}" "${geometry#* }" 2>/dev/null || true
  fi
done
