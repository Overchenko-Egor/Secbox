#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-systemd.sh must run as root" >&2
    exit 1
fi

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

create_system_user()
{
    user="$1"
    group="$2"

    if ! getent group "$group" >/dev/null 2>&1; then
        groupadd --system "$group"
    fi

    if ! getent passwd "$user" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "$group" \
            --home-dir /nonexistent \
            --shell /usr/sbin/nologin \
            "$user"
    fi
}

create_system_user secbox-web secbox-web
create_system_user secbox-ids secbox-ids
create_system_user secbox-deception secbox-deception

install -d -o root -g secbox-web -m 0710 /etc/secbox
install -d -o root -g root -m 0700 /etc/secbox/tls

install -d -o root -g root -m 0755 /var/lib/secbox
install -d -o secbox-web -g secbox-web -m 0700 /var/lib/secbox/web

install -d -o root -g root -m 0750 /var/lib/secbox/deception
install -d -o secbox-deception -g secbox-deception -m 0700 \
    /var/lib/secbox/deception/honeypot

install -d -o root -g secbox-deception -m 0750 \
    /var/lib/secbox/deception/cases

install -d -o root -g secbox-deception -m 0750 \
    /var/lib/secbox/deception/tls

install -d -o root -g root -m 0755 /run/secbox

install -D -m 0755 \
    "$PROJECT_ROOT/packaging/bin/secboxctl" \
    /usr/bin/secboxctl

install -D -m 0755 \
    "$PROJECT_ROOT/packaging/lib/secbox-firstboot" \
    /usr/lib/secbox/secbox-firstboot

if [ ! -f /etc/secbox/config.yml ]; then
    install \
        -o root \
        -g secbox-web \
        -m 0640 \
        "$PROJECT_ROOT/config/examples/secbox.yml" \
        /etc/secbox/config.yml
else
    chown root:secbox-web /etc/secbox/config.yml
    chmod 0640 /etc/secbox/config.yml
fi

for unit in "$PROJECT_ROOT"/packaging/systemd/secbox-*; do
    [ -f "$unit" ] || continue

    install \
        -D \
        -m 0644 \
        "$unit" \
        "/etc/systemd/system/$(basename "$unit")"
done

systemctl daemon-reload

systemctl enable \
    secbox-firstboot.service \
    secbox-action.socket \
    secbox-ids-action.socket \
    secbox-firewall.service \
    secbox-web.service \
    secbox-vpn.service \
    secbox-ids.service \
    secbox-deception-net.service \
    secbox-deception-topology.service \
    secbox-deception-runtime.service \
    secbox-deception-honeypot.service \
    secbox-deception-reaper.timer \
    secbox-doh-feed.timer
