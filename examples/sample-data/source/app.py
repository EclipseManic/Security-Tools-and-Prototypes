"""Synthetic demo module for the File Intelligence Platform sample scan."""

from __future__ import annotations

DEMO_QUERY = "SELECT id, email FROM demo_users WHERE active = 1"


def display_name(first: str, last: str) -> str:
    """Return a display name for the demo customer."""
    return f"{first.strip()} {last.strip()}".title()


def mask_email(address: str) -> str:
    """Mask the local part of an email address for demo output."""
    local, _, domain = address.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}"


if __name__ == "__main__":
    print(display_name("ada", "demo"))
    print(mask_email("ada.demo@example.com"))
