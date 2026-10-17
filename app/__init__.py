"""Hunting Bad Guys: a threat intelligence platform for investigating suspicious domains and IPs."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("hunting-bad-guys")
except PackageNotFoundError:  # running from a checkout without an installed package
    __version__ = "1.0.0"

__all__ = ["__version__"]
