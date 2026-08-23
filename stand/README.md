# Capture stand

The capture stand records the network traffic of a browser and of your own
binaries at the same time, then compares their TLS, DTLS and QUIC handshakes.
Use it to check whether a client built with `headlessclient` produces the same
wire fingerprint as Chrome.

The stand runs a pinned version of Chromium inside a Docker container. Analysis
also runs inside the container, so your host does not need Wireshark, tshark, or
Go.

## Before you begin

Install Docker. The stand needs no other host software.

The container requires the `NET_ADMIN` and `SYS_ADMIN` capabilities. `stand.sh`
passes them automatically.

## Build the image

```
./stand.sh build
```

The build downloads packages from `snapshot.debian.org` at a fixed timestamp and
compiles the `wirediff` analysis tool. It takes several minutes the first time
and is cached afterwards.

Rebuild the image after you change any file under `container/`, `cmd/`, or
`internal/`. Those files are copied into the image, so edits on the host do not
reach a running container until you rebuild.

## Record a capture

To record a browser visiting a page for 30 seconds:

```
./stand.sh run --secs 30 --url https://example.com/ --out ./captures/example
```

To record a browser and one of your own binaries at the same time:

```
./stand.sh run --secs 30 --url https://example.com/ \
    --role probe:/path/to/probe \
    --role-args probe:"https://example.com/ 3" \
    --out ./captures/example
```

If you omit `--secs`, the browser stays open and the capture continues until you
press Enter. Use this to sign in to a site or to drive a page by hand.

While the capture runs, open the browser at
`http://localhost:6090/vnc.html?autoconnect=1&resize=remote`. To change the
port, set the `HC_STAND_WEB_PORT` environment variable.

### `run` options

| Option | Description |
| --- | --- |
| `--secs N` | Stop the capture after N seconds. Without it, the capture stops when you press Enter. |
| `--url URL` | The page the browser opens. Defaults to `https://example.com/`. |
| `--out DIR` | Where to write the capture on the host. Defaults to `captures/<timestamp>`. |
| `--role NAME:PATH` | Add a role that runs the binary at PATH. Repeatable. |
| `--role-args NAME:ARGS` | Command-line arguments for a role. Repeatable. |
| `--file PATH` | Copy a file into the container at `/stand/files/<basename>`. Repeatable. Use it for cookie files and other inputs. |
| `--browser-flags FLAGS` | Extra command-line flags for Chromium. |
| `--keep-profile` | Reuse the browser profile from the previous run instead of deleting it. |
| `--no-browser` | Do not start the browser. Requires at least one `--role`. |

## Compare two captures

```
./stand.sh diff ./captures/example -sni example.com
```

With one role in the directory, `diff` prints a summary. With two roles, it also
prints a field-by-field comparison. `diff` copies the directory into the
container and runs the analysis there.

### `diff` options

| Option | Description |
| --- | --- |
| `-sni HOST` | Only consider handshakes whose target contains this string. |
| `-a TARGET` | Compare this target from the first role. Use with `-b`. |
| `-b TARGET` | Compare this target from the second role. Use with `-a`. |
| `-client-only` | Ignore server hellos. Defaults to `true`. |

Without `-a` and `-b`, the tool compares every target that both roles reached.

### Fields the comparison covers

JA4, record version, hello version, session ID length, cipher count, cipher
order, extension count, extension set, extension order, supported versions,
supported groups, key share, signature algorithms, ALPN, point formats,
compression, and `use_srtp`.

The comparison also reports whether the extension order and the cipher order
stay the same across the handshakes in a capture. Chrome shuffles its extensions
on every connection, so a client that mimics Chrome must shuffle as well. The
tool reports `shuffled`, `stable`, or `unknown` when there is only one
handshake to compare.

**Note:** GREASE values are random on every connection and appear in the cipher
list, the extension list, `supported_versions`, `supported_groups`, and
`key_share`. The tool removes them before comparing. Without this, two captures
from the same browser would report differences.

## Stop the stand

```
./stand.sh down
```

This removes the container. The next `run` or `diff` creates a new one.

## Output files

Each capture directory contains the following files for every role:

| File | Contents |
| --- | --- |
| `<role>.pcap` | Captured packets. |
| `<role>.keys` | TLS session keys in `SSLKEYLOGFILE` format. Use them to decrypt the pcap. |
| `<role>.stdout.log` | Standard output and standard error of the role. |
| `<role>.tcpdump.log` | Standard error of tcpdump. Check this if a pcap is empty. |

The directory also contains `manifest.json`, which records the capture time, the
versions of Chromium, tshark, and tcpdump, the kernel version, and the address
and command line of every role.

**Caution:** Capture files contain session cookies and TLS keys for every site
the roles visited. Do not commit them and do not share them. The `captures/`
directory is listed in `.gitignore`.

## How roles work

A role is a name paired with a command. The stand gives each role its own
network namespace, a veth pair, an address in `10.201.<n>.2/30`, a default
route, NAT, and its own `resolv.conf`. It then runs `tcpdump` on the host end of
the veth pair and sets `SSLKEYLOGFILE` for the role.

Because each role has its own namespace, no other role's packets can appear in
its capture. You do not need to filter the capture by address or port to tell
roles apart.

Role names are arbitrary, except for `browser`, which the stand uses for the
Chromium role. To use that name for your own binary, pass `--no-browser`.

## What the image pins

| Component | Version |
| --- | --- |
| Base image | `debian@sha256:3a39a059...` (trixie) |
| Package snapshot | `20260821T000000Z` |
| Chromium | `151.0.7922.169-1~deb13u1` |
| tshark | 4.4.16 |
| Go toolchain for `wirediff` | `golang@sha256:1d414b03...` |

tshark 4.4.16 comes from trixie because the version in bookworm does not support
the `ja4` field.

## Repository layout

| Path | Contents |
| --- | --- |
| `stand.sh` | Host script. The only file that calls Docker. |
| `container/capture.sh` | Creates the namespaces, runs the roles, writes the manifest. |
| `container/chromium.sh` | Starts Chromium for the `browser` role. |
| `container/display.sh` | Starts the VNC server and the web client. Runs in the main namespace. |
| `cmd/wirediff` | Analysis tool. |
| `internal/wire` | Handshake parser. |

`cmd/wirediff` and `internal/wire` form a separate Go module with its own
`go.mod`, so that the packet-capture dependencies do not become dependencies of
the `headlessclient` library.

`internal/wire` is a copy of the parser from the `dowe` project, with server
name, `supported_versions`, `key_share`, and JA4 support added.

## Troubleshooting

### Your change to a script has no effect

Rebuild the image and remove the container:

```
./stand.sh build
./stand.sh down
```

`stand.sh` recreates the container when the image ID changes, but it does not
recreate it when only the container's run options change.

### A capture contains traffic you did not expect

Chromium contacts Google services even with `--disable-background-networking`.
You will see requests to hosts such as `accounts.google.com` and
`update.googleapis.com` in the browser capture. This traffic is harmless because
each role is isolated, but you should scope the analysis with `-sni`.

### A role's pcap is empty

Check `<role>.tcpdump.log` and `<role>.stdout.log`. A common cause is a command
that failed to start. The image contains `python3` and Chromium but does not
contain `curl`.

### Traffic between two processes in one role is missing

`tcpdump` runs on the host end of the veth pair, so it does not see traffic that
stays on the loopback interface. To capture loopback traffic, add a second
`tcpdump` inside the namespace:

```
ip netns exec <role> tcpdump -i lo -s 0 -U -w <role>.lo.pcap
```

`-i any` also works and the parser reads it, but it records the veth traffic as
well, which the role's main capture already contains. Use `-i lo` to keep the
two captures separate.

### The browser stream does not load

Check that the container is running and that no other process holds the port.
The `dowe` project uses port 6080; the stand uses 6090 to avoid a conflict.
