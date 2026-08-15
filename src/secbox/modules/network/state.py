"""Runtime network interface state models."""

from pydantic import BaseModel, ConfigDict


class NetworkAddress(BaseModel):
    """IP address assigned to a network interface."""

    model_config = ConfigDict(extra="forbid")

    family: str
    address: str
    prefixlen: int
    scope: str | None = None


class NetworkInterfaceState(BaseModel):
    """Observed state of a Linux network interface."""

    model_config = ConfigDict(extra="forbid")

    name: str
    mac: str | None = None
    mtu: int
    operstate: str
    flags: list[str]
    addresses: list[NetworkAddress]
    is_loopback: bool
