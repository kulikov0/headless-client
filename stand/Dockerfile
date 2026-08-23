FROM golang@sha256:1d414b0376b53ec94b9a2493229adb81df8b90af014b18619732f1ceaaf7234a AS tools

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -o /out/wirediff ./cmd/wirediff

FROM debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

ENV DEBIAN_FRONTEND=noninteractive

ARG SNAPSHOT=20260821T000000Z
ARG CHROMIUM_VERSION=151.0.7922.169-1~deb13u1

RUN set -eux; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie main\n' "$SNAPSHOT" > /etc/apt/sources.list; \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ trixie-security main\n' "$SNAPSHOT" >> /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    apt-get install -y --no-install-recommends \
        "chromium=$CHROMIUM_VERSION" \
        tigervnc-standalone-server websockify novnc matchbox-window-manager xdotool \
        tcpdump tshark \
        iproute2 iptables \
        ca-certificates \
        fonts-liberation fonts-noto-color-emoji \
        procps jq; \
    rm -rf /var/lib/apt/lists/*; \
    chromium --version

COPY --from=tools /out/wirediff /usr/local/bin/wirediff
COPY container/ /stand/
RUN chmod +x /stand/*.sh

CMD ["sleep", "infinity"]
