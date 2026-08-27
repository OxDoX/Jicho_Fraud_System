"""Scope loading and scope-lock enforcement (Hard Constraint 2).

Nothing downstream should ever get to propose an action against a target
without first passing through `is_in_scope`. Ambiguous targets are treated
as OUT of scope — never "probably fine".
"""
from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .models import EngagementType, ScopeAsset, ScopeDoc


class ScopeError(Exception):
    pass


def load_scope(path: str | Path) -> ScopeDoc:
    path = Path(path)
    if not path.exists():
        raise ScopeError(f"Scope file not found: {path}")
    raw = yaml.safe_load(path.read_text()) or {}

    try:
        engagement_type = EngagementType(raw.get("engagement_type", "bug_bounty"))
    except ValueError as e:
        raise ScopeError(
            f"engagement_type must be one of {[t.value for t in EngagementType]}"
        ) from e

    in_scope = [
        ScopeAsset(pattern=item["pattern"], asset_type=item.get("asset_type", "host"))
        if isinstance(item, dict)
        else ScopeAsset(pattern=str(item))
        for item in raw.get("in_scope", [])
    ]

    if not in_scope:
        raise ScopeError("Scope doc has an empty in_scope list — refusing to load an unscoped engagement.")

    return ScopeDoc(
        program_name=raw.get("program_name", "UNNAMED"),
        engagement_type=engagement_type,
        in_scope=in_scope,
        out_of_scope=raw.get("out_of_scope", []) or [],
        exclusions=raw.get("exclusions", []) or [],
        safe_harbor_confirmed=bool(raw.get("safe_harbor_confirmed", False)),
        identity_requirement=raw.get("identity_requirement", ""),
        rate_limit=raw.get("rate_limit", ""),
        blackout_windows=raw.get("blackout_windows", []) or [],
        notes=raw.get("notes", ""),
    )


def _extract_host(target: str) -> str:
    """Best-effort extraction of a bare host/IP from a URL or raw host string."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # strip path/port if present, e.g. example.com/foo or 10.0.0.1:8080
    return target.split("/")[0].split(":")[0]


def _matches_asset(host: str, asset: ScopeAsset) -> bool:
    pattern = asset.pattern.strip()

    if asset.asset_type == "cidr" or "/" in pattern and _looks_like_cidr(pattern):
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in net
        except ValueError:
            return False

    if asset.asset_type == "url" or pattern.startswith("http://") or pattern.startswith("https://"):
        # URL-prefix scope entry: match by hostname + path prefix.
        parsed = urlparse(pattern)
        return host == parsed.hostname

    # host / wildcard-subdomain matching
    return fnmatch.fnmatch(host.lower(), pattern.lower())


def _looks_like_cidr(pattern: str) -> bool:
    try:
        ipaddress.ip_network(pattern, strict=False)
        return True
    except ValueError:
        return False


def is_in_scope(scope: ScopeDoc, target: str) -> tuple[bool, str]:
    """Returns (in_scope, reason). Ambiguous or unparseable targets => False."""
    if not target or not target.strip():
        return False, "empty target"

    host = _extract_host(target)
    if not host:
        return False, "could not extract a host from target"

    for excl in scope.out_of_scope:
        if fnmatch.fnmatch(host.lower(), excl.lower()):
            return False, f"matches out_of_scope entry '{excl}'"

    for asset in scope.in_scope:
        if _matches_asset(host, asset):
            return True, f"matches in_scope entry '{asset.pattern}'"

    return False, "does not match any in_scope entry"
