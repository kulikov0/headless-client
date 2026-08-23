#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
image=headlessclient-stand
container=hc-stand
display=:100
vnc_port=5900
web_port=${HC_STAND_WEB_PORT:-6090}

usage() {
  cat >&2 <<'EOF'
usage:
  stand.sh build
  stand.sh run [--secs N] [--url URL] [--keep-profile] [--browser-flags FLAGS]
               [--out DIR] [--no-browser]
               [--role NAME:PATH]... [--role-args NAME:ARGS]... [--file PATH]...
  stand.sh diff DIR [wirediff args]
  stand.sh down

run captures every role into DIR: <role>.pcap, <role>.keys, <role>.stdout.log, manifest.json.
Each role gets its own netns, so no other role's packets can land in its capture.
--role adds a binary role, --file copies a file its arguments can point at under
/stand/files. The browser is a role too, named browser, driven by --url.
Without --secs the browser stays up and the capture stops when you press Enter.
diff runs the analysis inside the container, so the host needs no tshark and no Go.
EOF
  exit 1
}

in_container() {
  docker exec "$container" "$@"
}

in_container_detached() {
  docker exec -d "$container" "$@"
}

start_container() {
  docker inspect "$image" >/dev/null 2>&1 || { echo "image missing, run: stand.sh build" >&2; exit 1; }

  if docker inspect "$container" >/dev/null 2>&1 &&
     [ "$(docker inspect -f '{{.Image}}' "$container")" != "$(docker inspect -f '{{.Id}}' "$image")" ]; then
    echo "image changed, recreating container"
    docker rm -f "$container" >/dev/null
  fi

  if ! docker inspect "$container" >/dev/null 2>&1; then
    docker run -d --name "$container" --init \
      --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
      -p "$web_port:$web_port" \
      "$image" >/dev/null
  elif [ "$(docker inspect -f '{{.State.Running}}' "$container")" != true ]; then
    docker start "$container" >/dev/null
  fi
}

case ${1:-} in
  build)
    docker build -t "$image" "$here"
    ;;

  diff)
    shift
    [ $# -ge 1 ] || usage
    source=$1
    shift
    [ -d "$source" ] || { echo "not a capture directory: $source" >&2; exit 1; }

    start_container
    in_container rm -rf /stand/diff
    in_container mkdir -p /stand/diff
    docker cp "$source/." "$container:/stand/diff/"
    in_container wirediff "$@" /stand/diff
    ;;

  down)
    docker rm -f "$container" >/dev/null 2>&1 || true
    echo "stand down"
    ;;

  run)
    shift
    secs=
    url=https://example.com/
    out=$here/captures/$(date -u +%Y%m%dT%H%M%SZ)
    browser=1
    keep_profile=
    browser_flags=
    declare -A role_binaries=()
    declare -A role_arguments=()
    role_names=()
    files=()
    while [ $# -gt 0 ]; do
      case $1 in
        --secs) secs=$2; shift 2 ;;
        --url) url=$2; shift 2 ;;
        --role)
          [ "${2#*:}" != "$2" ] || { echo "--role wants NAME:PATH, got $2" >&2; exit 1; }
          role_binaries[${2%%:*}]=${2#*:}
          role_names+=("${2%%:*}")
          shift 2 ;;
        --role-args)
          [ "${2#*:}" != "$2" ] || { echo "--role-args wants NAME:ARGS, got $2" >&2; exit 1; }
          role_arguments[${2%%:*}]=${2#*:}
          shift 2 ;;
        --file) files+=("$2"); shift 2 ;;
        --out) out=$2; shift 2 ;;
        --no-browser) browser=0; shift ;;
        --keep-profile) keep_profile=--keep-profile; shift ;;
        --browser-flags) browser_flags="-- $2"; shift 2 ;;
        *) usage ;;
      esac
    done

    if [ "$browser" -eq 0 ] && [ ${#role_names[@]} -eq 0 ]; then
      echo "nothing to capture: pass --role or drop --no-browser" >&2
      exit 1
    fi
    if [ "$browser" -eq 1 ] && [ -n "${role_binaries[browser]:-}" ]; then
      echo "role name 'browser' is taken by the browser, pass --no-browser or rename" >&2
      exit 1
    fi

    start_container

    in_container rm -rf /stand/out /stand/files
    in_container mkdir -p /stand/out /stand/profiles /stand/files

    for file in ${files[@]+"${files[@]}"}; do
      [ -f "$file" ] || { echo "file not found: $file" >&2; exit 1; }
      docker cp "$file" "$container:/stand/files/$(basename "$file")"
    done

    roles=()
    if [ "$browser" -eq 1 ]; then
      in_container_detached /stand/display.sh "$display" "$vnc_port" "$web_port"
      sleep 2
      roles+=("browser=/stand/chromium.sh --display $display --url '$url' $keep_profile $browser_flags")
    fi
    for name in ${role_names[@]+"${role_names[@]}"}; do
      binary=${role_binaries[$name]}
      [ -f "$binary" ] || { echo "role binary not found: $binary" >&2; exit 1; }
      docker cp "$binary" "$container:/stand/$name"
      in_container chmod +x "/stand/$name"
      roles+=("$name=/stand/$name ${role_arguments[$name]:-}")
    done

    if [ "$browser" -eq 1 ]; then
      echo "browser stream: http://localhost:$web_port/vnc.html?autoconnect=1&resize=remote"
    fi

    if [ -n "$secs" ]; then
      in_container /stand/capture.sh /stand/out "$secs" "${roles[@]}"
    else
      in_container_detached /stand/capture.sh /stand/out 0 "${roles[@]}"
      echo "capturing, press Enter to stop"
      read -r _
      in_container pkill -TERM -f '/stand/capture.sh' >/dev/null 2>&1 || true
      for _ in $(seq 1 60); do
        in_container test -f /stand/out/manifest.json >/dev/null 2>&1 && break
        sleep 1
      done
    fi

    mkdir -p "$out"
    docker cp "$container:/stand/out/." "$out/"
    echo "captured into $out"
    ls -1 "$out"
    ;;

  *)
    usage
    ;;
esac
