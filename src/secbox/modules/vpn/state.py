"""Runtime state inspection for SecBox VPN tunnels."""

import subprocess


class VpnStateError(RuntimeError):
    """Raised when VPN runtime state cannot be inspected."""


def get_wireguard_status(interface: str) -> str:
    try:
        result = subprocess.run(
            [
                "/usr/bin/wg",
                "show",
                interface,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip()

        raise VpnStateError(
            f"failed to read WireGuard interface "
            f"{interface}: {message}"
        ) from error

    return result.stdout.rstrip()
