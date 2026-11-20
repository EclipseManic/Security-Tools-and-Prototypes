"""ServiceSentinel Web: Windows service inventory, hunting and triage console."""

from .config import APP_NAME, VERSION

__all__ = ["APP_NAME", "VERSION", "create_app"]


def create_app(*args, **kwargs):
    from .server import create_app as factory

    return factory(*args, **kwargs)
