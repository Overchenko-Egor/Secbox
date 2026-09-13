#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

install -D -m 0755 \
    "$PROJECT_ROOT/packaging/bin/secboxctl" \
    /usr/bin/secboxctl

install -D -m 0644 \
    "$PROJECT_ROOT/packaging/systemd/secbox-doh-feed.service" \
    /etc/systemd/system/secbox-doh-feed.service

install -D -m 0644 \
    "$PROJECT_ROOT/packaging/systemd/secbox-doh-feed.timer" \
    /etc/systemd/system/secbox-doh-feed.timer

install -D -m 0644 \
    "$PROJECT_ROOT/packaging/systemd/secbox-ids.service" \
    /etc/systemd/system/secbox-ids.service

install -D -m 0644 \
    "$PROJECT_ROOT/packaging/systemd/secbox-vpn.service" \
    /etc/systemd/system/secbox-vpn.service

systemctl daemon-reload
