from pathlib import Path

from secbox.modules.network.models import (
    NetworkConfig,
    NetworkInterfaceConfig,
)
from secbox.modules.network.renderer import render_networkd


def test_render_dhcp_interface(tmp_path: Path) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            )
        ]
    )

    files = render_networkd(
        config,
        tmp_path,
    )

    assert len(files) == 1

    content = files[0].read_text(
        encoding="utf-8",
    )

    assert "Name=ens33" in content
    assert "DHCP=ipv4" in content
    assert "IPv6AcceptRA=no" in content


def test_render_static_interface(tmp_path: Path) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            )
        ]
    )

    files = render_networkd(
        config,
        tmp_path,
    )

    content = files[0].read_text(
        encoding="utf-8",
    )

    assert "Name=ens36" in content
    assert "Address=192.168.50.1/24" in content
    assert "DHCP=no" in content


def test_render_disabled_interface(tmp_path: Path) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens37",
                role="unused",
                ipv4_method="disabled",
            )
        ]
    )

    files = render_networkd(
        config,
        tmp_path,
    )

    content = files[0].read_text(
        encoding="utf-8",
    )

    assert "Name=ens37" in content
    assert "DHCP=no" in content
    assert "LinkLocalAddressing=no" in content


def test_old_rendered_files_are_removed(tmp_path: Path) -> None:
    old_file = tmp_path / "99-old.network"
    old_file.write_text(
        "old",
        encoding="utf-8",
    )

    config = NetworkConfig()

    render_networkd(
        config,
        tmp_path,
    )

    assert not old_file.exists()


def test_filenames_are_deterministic(tmp_path: Path) -> None:
    config = NetworkConfig(
        interfaces=[
            NetworkInterfaceConfig(
                name="ens36",
                role="lan",
                ipv4_method="static",
                ipv4_address="192.168.50.1/24",
            ),
            NetworkInterfaceConfig(
                name="ens33",
                role="wan",
                ipv4_method="dhcp",
            ),
        ]
    )

    files = render_networkd(
        config,
        tmp_path,
    )

    assert files[0].name == "10-secbox-ens33.network"
    assert files[1].name == "10-secbox-ens36.network"
