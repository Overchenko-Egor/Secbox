"""Configuration models for SecBox content filtering."""

from ipaddress import IPv4Address
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


def normalize_domain(value: str) -> str:
    """Normalize and validate a domain name."""

    domain = value.strip().lower().rstrip(".")

    if not domain:
        raise ValueError("domain cannot be empty")

    if len(domain) > 253:
        raise ValueError("domain is too long")

    labels = domain.split(".")

    for label in labels:
        if not label:
            raise ValueError("domain contains an empty label")

        if len(label) > 63:
            raise ValueError("domain label is too long")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError(
                "domain labels must not start or end with '-'"
            )

        allowed = set(
            "abcdefghijklmnopqrstuvwxyz0123456789-"
        )

        if any(character not in allowed for character in label):
            raise ValueError(
                "domain contains unsupported characters"
            )

    return domain


class DnsFilterConfig(BaseModel):
    """DNS filtering configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    listen_interface: str
    listen_address: IPv4Address
    upstream_servers: list[IPv4Address] = Field(
        default_factory=list
    )

    @field_validator("listen_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "listen_interface cannot be empty"
            )

        if value == "lo":
            raise ValueError(
                "content filter cannot listen on loopback"
            )

        return value

    @field_validator("upstream_servers")
    @classmethod
    def validate_upstream_servers(
        cls,
        value: list[IPv4Address],
    ) -> list[IPv4Address]:
        if not value:
            raise ValueError(
                "at least one upstream DNS server is required"
            )

        if len(set(value)) != len(value):
            raise ValueError(
                "upstream DNS servers must be unique"
            )

        return value


class ContentFilterPolicyConfig(BaseModel):
    """Domain filtering policy."""

    model_config = ConfigDict(extra="forbid")

    default_action: Literal["allow", "block"] = "allow"

    blocked_domains: list[str] = Field(
        default_factory=list
    )

    allowed_domains: list[str] = Field(
        default_factory=list
    )

    @field_validator(
        "blocked_domains",
        "allowed_domains",
    )
    @classmethod
    def normalize_domains(
        cls,
        value: list[str],
    ) -> list[str]:
        normalized = [
            normalize_domain(domain)
            for domain in value
        ]

        if len(set(normalized)) != len(normalized):
            raise ValueError(
                "domain lists must not contain duplicates"
            )

        return normalized

    @model_validator(mode="after")
    def validate_domain_conflicts(
        self,
    ) -> "ContentFilterPolicyConfig":
        conflicts = (
            set(self.blocked_domains)
            & set(self.allowed_domains)
        )

        if conflicts:
            joined = ", ".join(sorted(conflicts))

            raise ValueError(
                "domains cannot be both allowed and blocked: "
                f"{joined}"
            )

        return self


class DohFilterConfig(BaseModel):
    """DNS-over-HTTPS filtering configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True

    resolver_addresses: list[IPv4Address] = Field(
        default_factory=list
    )

    managed_feed_enabled: bool = False

    managed_addresses: list[IPv4Address] = Field(
        default_factory=list
    )

    @field_validator(
        "resolver_addresses",
        "managed_addresses",
    )
    @classmethod
    def validate_resolver_addresses(
        cls,
        value: list[IPv4Address],
    ) -> list[IPv4Address]:
        if len(set(value)) != len(value):
            raise ValueError(
                "DoH resolver addresses must be unique"
            )

        return value

    @model_validator(mode="after")
    def validate_address_conflicts(
        self,
    ) -> "DohFilterConfig":
        conflicts = (
            set(self.resolver_addresses)
            & set(self.managed_addresses)
        )

        if conflicts:
            joined = ", ".join(
                str(address)
                for address in sorted(
                    conflicts,
                    key=int,
                )
            )

            raise ValueError(
                "DoH resolver addresses cannot be both "
                f"manual and managed: {joined}"
            )

        return self


class EncryptedDnsFilterConfig(BaseModel):
    """Encrypted DNS filtering configuration."""

    model_config = ConfigDict(extra="forbid")

    block_dot: bool = True
    block_doq: bool = True

    doh: DohFilterConfig = Field(
        default_factory=DohFilterConfig,
    )



class ContentFilterLoggingConfig(BaseModel):
    """Content-filter logging settings."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ContentFilterConfig(BaseModel):
    """SecBox content filtering configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False

    dns: DnsFilterConfig

    policy: ContentFilterPolicyConfig = Field(
        default_factory=ContentFilterPolicyConfig,
    )

    encrypted_dns: EncryptedDnsFilterConfig = Field(
        default_factory=EncryptedDnsFilterConfig,
    )

    logging: ContentFilterLoggingConfig = Field(
        default_factory=ContentFilterLoggingConfig,
    )
