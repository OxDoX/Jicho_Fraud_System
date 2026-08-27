"""
On-premises Update Agent — the narrow, one-way, cryptographically verified
cloud update channel described in JFS_Deployment_Architecture.docx
(Section 5) and summarized in CLAUDE.md Section 10. This is the one piece
of that architecture document with no code behind it before this module —
everything else described there (rules engine, hunting, dashboard, local
data store) already exists elsewhere in this package.

The non-negotiable shape, straight from the deployment doc:
  1. Pull-only. This agent only ever initiates outbound requests; nothing
     in this codebase accepts an inbound connection from a vendor cloud
     service. fetch_from_url() is one concrete, swappable transport for
     that pull — see jicho/realtime.py for the same transport-agnostic
     pattern applied to real-time scoring.
  2. Verify before trust. A package is checked for BOTH checksum integrity
     and Ed25519 signature authenticity before anything else touches it.
     Strictly, a valid signature over the payload already proves both
     properties on its own; the separate checksum check exists because the
     deployment doc calls it out as a distinct gate an operator can verify
     with a plain `sha256sum`, and because it gives a clearer audit-log
     distinction between "corrupted in transit" and "not from the vendor"
     — either failure is treated identically (discard, log as a security
     event), so this isn't a security gap, just a diagnostic nicety.
  3. Stage, never auto-promote. A verified package lands in a staging
     area. promote() is a separate, explicit call requiring a named human
     reviewer — mirroring the same human-review-before-deploy principle
     CLAUDE.md already establishes for AI-drafted rules and prevention
     rule whitelisting. Nothing in this module calls promote() on its own.
  4. Fail safe. pull_and_stage() never raises: a network failure or a
     failed verification is logged and returns None, so a broken or
     compromised update source can never block, degrade, or pause
     detection/alerting — exactly the guarantee the deployment doc
     requires in Section 5.4.
  5. Rollback is local. The last MAX_ROLLBACK_HISTORY approved configs are
     kept on disk; rolling back needs no cloud connectivity.

What this reference implementation does NOT do, stated plainly:
  - It only automates promotion for `config_update` packages (a threshold
    retune, applied to a YAML file). A `new_rule` package still requires a
    human to paste reviewed code into jicho/rules/known_patterns.py per
    the AI rule-drafting workflow's own review step (CLAUDE.md Section
    5.3) — auto-applying a code change would violate that same principle.
    `software_patch` packages are entirely out of scope here; patching
    this codebase itself isn't something this codebase can safely do to
    itself. `threat_advisory` packages carry no payload to apply at all.
  - The CAB/Agile human review step (deployment doc Section 6, steps 4-5:
    auto-drafted change ticket, risk-officer sign-off) is a governance
    process this module supports with an audit trail and a regression
    report, not something code can perform on an institution's behalf.
  - promote()'s YAML rewrite uses plain PyYAML, which does not preserve
    comments in config/default_config.yaml — an accepted limitation for a
    reference implementation, not something to paper over.
"""

import hashlib
import json
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from jicho.config import EngineConfig
from jicho.engine import FraudEngine
from jicho.exceptions import UpdatePackageError
from jicho.logging_config import get_logger

logger = get_logger(__name__)

PackageType = Literal["config_update", "new_rule", "threat_advisory", "software_patch"]
MAX_ROLLBACK_HISTORY = 3


@dataclass
class UpdatePackage:
    version: str
    package_type: PackageType
    payload: bytes  # for config_update: UTF-8 JSON bytes of {config_key: new_value, ...}
    description: str
    published_at: str
    checksum_sha256: str  # vendor-claimed SHA-256 hex digest of `payload`
    signature: bytes  # Ed25519 signature over `payload`, by the vendor's release key


@dataclass
class StagedUpdate:
    package: UpdatePackage
    staged_at: str
    staged_path: str


@dataclass
class RegressionResult:
    """Before/after alert comparison for a staged config_update, run against
    the institution's own historical sample — deployment doc Table 4, step 3.
    """

    before_alert_count: int
    after_alert_count: int
    before_by_rule: dict[str, int]
    after_by_rule: dict[str, int]

    def summary(self) -> str:
        changed_rules = (set(self.before_by_rule) | set(self.after_by_rule))
        changed = {
            rid: (self.before_by_rule.get(rid, 0), self.after_by_rule.get(rid, 0))
            for rid in changed_rules
            if self.before_by_rule.get(rid, 0) != self.after_by_rule.get(rid, 0)
        }
        if not changed:
            return f"No change in alert output ({self.before_alert_count} alerts before and after)."
        lines = [f"Alert count changed: {self.before_alert_count} -> {self.after_alert_count}"]
        for rid in sorted(changed, key=lambda r: int(r[1:]) if r[1:].isdigit() else 0):
            before, after = changed[rid]
            lines.append(f"  {rid}: {before} -> {after}")
        return "\n".join(lines)


def compute_checksum(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_package(package: UpdatePackage, public_key_pem: bytes) -> None:
    """Raises UpdatePackageError on any checksum or signature failure. See
    the module docstring for why both are checked and why either failing
    is handled identically.
    """
    actual_checksum = compute_checksum(package.payload)
    if actual_checksum != package.checksum_sha256:
        raise UpdatePackageError(
            f"Checksum mismatch for package {package.version}: "
            f"expected {package.checksum_sha256}, computed {actual_checksum}"
        )

    public_key = load_pem_public_key(public_key_pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise UpdatePackageError("Configured public key is not an Ed25519 key")
    try:
        public_key.verify(package.signature, package.payload)
    except InvalidSignature as e:
        raise UpdatePackageError(
            f"Signature verification failed for package {package.version} — discarding; this may "
            "indicate a compromised or spoofed update source"
        ) from e


class UpdateAgent:
    """Pull → verify → stage → (human-gated) promote, plus rollback and a
    connectivity health check. See the module docstring for the full
    governance model this implements.
    """

    def __init__(self, public_key_pem: bytes, staging_dir: str, state_dir: str):
        self.public_key_pem = public_key_pem
        self.staging_dir = staging_dir
        self.state_dir = state_dir
        os.makedirs(staging_dir, exist_ok=True)
        os.makedirs(state_dir, exist_ok=True)

    def _audit_log(self, event: str, **fields) -> None:
        # Append-only by construction (mode "a") — every pull attempt,
        # verification result, staging event, and promotion/rejection
        # decision accumulates here for IT audit and regulator review
        # (deployment doc Section 7), never overwritten.
        record = {"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **fields}
        path = os.path.join(self.state_dir, "audit_log.jsonl")
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
        logger.info(f"UpdateAgent audit: {event} {fields}")

    def pull_and_stage(self, fetch_fn: Callable[[], "UpdatePackage | None"]) -> "StagedUpdate | None":
        """Calls `fetch_fn` (a concrete transport, e.g. fetch_from_url or
        fetch_from_file below) and stages the result if it verifies.
        Never raises — see the module docstring's "fail safe" point.
        """
        self._touch_last_pull_attempt()
        try:
            package = fetch_fn()
        except Exception as e:
            self._audit_log("pull_failed", error=str(e))
            logger.error(f"Update pull failed: {e}")
            return None

        if package is None:
            self._audit_log("pull_no_update_available")
            return None

        try:
            verify_package(package, self.public_key_pem)
        except UpdatePackageError as e:
            self._audit_log("verification_failed", version=package.version, error=str(e))
            logger.error(str(e))
            return None

        self._audit_log("pull_verified", version=package.version, package_type=package.package_type)
        return self._stage(package)

    def _stage(self, package: UpdatePackage) -> StagedUpdate:
        staged_path = os.path.join(self.staging_dir, f"{package.version}.json")
        with open(staged_path, "wb") as f:
            f.write(package.payload)
        staged = StagedUpdate(
            package=package, staged_at=datetime.now(timezone.utc).isoformat(), staged_path=staged_path
        )
        self._audit_log("staged", version=package.version, path=staged_path)
        return staged

    def list_staged(self) -> list[str]:
        return sorted(os.listdir(self.staging_dir))

    def run_regression_test(self, staged: StagedUpdate, sample_df, current_config: EngineConfig) -> RegressionResult:
        """Runs the institution's own historical sample against the
        currently-approved config and the staged config, and reports the
        alert-count difference — deployment doc Table 4, step 3.
        """
        if staged.package.package_type != "config_update":
            raise UpdatePackageError(
                f"Automated regression testing is only implemented for config_update packages in "
                f"this reference implementation, not '{staged.package.package_type}'"
            )

        overrides = json.loads(staged.package.payload)
        staged_config = EngineConfig(**{**current_config.model_dump(), **overrides})

        before_alerts = FraudEngine(config=current_config).run(sample_df)
        after_alerts = FraudEngine(config=staged_config).run(sample_df)

        def _by_rule(alerts):
            counts: dict[str, int] = {}
            for a in alerts:
                counts[a.rule_id] = counts.get(a.rule_id, 0) + 1
            return counts

        return RegressionResult(
            before_alert_count=len(before_alerts),
            after_alert_count=len(after_alerts),
            before_by_rule=_by_rule(before_alerts),
            after_by_rule=_by_rule(after_alerts),
        )

    def promote(self, staged: StagedUpdate, config_path: str, reviewer: str, decision_note: str) -> None:
        """The explicit, human-gated production promotion step (deployment
        doc Table 4, steps 5-7). Never called automatically by this module.
        """
        if staged.package.package_type != "config_update":
            raise UpdatePackageError(
                f"promote() only applies config_update packages directly; a '{staged.package.package_type}' "
                "package requires the manual code-review step described in CLAUDE.md Section 5.3, "
                "not an automated promotion"
            )
        if not reviewer:
            raise ValueError("promote() requires a named reviewer — this is a human-accountable action")

        self._push_rollback_history(config_path)

        overrides = json.loads(staged.package.payload)
        current: dict = {}
        if os.path.exists(config_path):
            with open(config_path) as f:
                current = yaml.safe_load(f) or {}
        current.update(overrides)
        with open(config_path, "w") as f:
            yaml.safe_dump(current, f)

        self._audit_log(
            "promoted",
            version=staged.package.version,
            reviewer=reviewer,
            decision_note=decision_note,
            config_path=config_path,
        )

    def reject(self, staged: StagedUpdate, reviewer: str, reason: str) -> None:
        if os.path.exists(staged.staged_path):
            os.remove(staged.staged_path)
        self._audit_log("rejected", version=staged.package.version, reviewer=reviewer, reason=reason)

    def _push_rollback_history(self, config_path: str) -> None:
        if not os.path.exists(config_path):
            return
        history_dir = os.path.join(self.state_dir, "rollback_history")
        os.makedirs(history_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        backup_path = os.path.join(history_dir, f"{timestamp}.yaml")
        shutil.copy2(config_path, backup_path)
        # Retain only the last MAX_ROLLBACK_HISTORY approved versions
        # (deployment doc Section 5.3: "retains the previous three
        # approved rule/config versions locally at all times").
        backups = sorted(os.listdir(history_dir))
        for stale in backups[:-MAX_ROLLBACK_HISTORY]:
            os.remove(os.path.join(history_dir, stale))

    def rollback(self, config_path: str) -> str:
        """Restores the most recently superseded config. Fully local and
        offline (Section 5.3) — no cloud connectivity involved. Returns
        the backup path restored from.
        """
        history_dir = os.path.join(self.state_dir, "rollback_history")
        backups = sorted(os.listdir(history_dir)) if os.path.isdir(history_dir) else []
        if not backups:
            raise UpdatePackageError("No previous approved version available to roll back to")
        latest_backup = os.path.join(history_dir, backups[-1])
        shutil.copy2(latest_backup, config_path)
        self._audit_log("rolled_back", restored_from=latest_backup, config_path=config_path)
        return latest_backup

    def _touch_last_pull_attempt(self) -> None:
        path = os.path.join(self.state_dir, "last_pull_attempt")
        with open(path, "w") as f:
            f.write(datetime.now(timezone.utc).isoformat())

    def health_check(self, max_days_since_last_pull: int = 7) -> bool:
        """Section 9.2: alert if no successful pull ATTEMPT (not necessarily
        one that found an update) has happened within a configurable
        threshold, so a silently-broken scheduler is never mistaken for "no
        new updates." Returns True if healthy.
        """
        path = os.path.join(self.state_dir, "last_pull_attempt")
        if not os.path.exists(path):
            return False
        with open(path) as f:
            last = datetime.fromisoformat(f.read().strip())
        age = datetime.now(timezone.utc) - last
        return age.days <= max_days_since_last_pull


def fetch_from_url(url: str, current_version: str, timeout: float = 30) -> "UpdatePackage | None":
    """Concrete transport: a single outbound HTTPS pull requesting only
    "what's new since version X" (deployment doc Section 5.2). Kept
    separate from UpdateAgent's verification/staging/governance logic,
    matching the transport-agnostic pattern in jicho/realtime.py — swapping
    this for a different transport touches nothing else in this module.
    Expects a 204 (or empty body) for "no update available."
    """
    import requests

    response = requests.get(url, params={"since": current_version}, timeout=timeout)
    response.raise_for_status()
    if response.status_code == 204 or not response.content:
        return None
    data = response.json()
    return _package_from_dict(data)


def fetch_from_file(path: str) -> UpdatePackage:
    """Concrete transport for air-gapped institutions: manual update import
    via removable media, following the institution's own data-import
    security procedure (deployment doc Section 5.4 and Section 11).
    `path` is a JSON manifest with the same fields fetch_from_url's
    response would carry.
    """
    with open(path) as f:
        data = json.load(f)
    return _package_from_dict(data)


def _package_from_dict(data: dict) -> UpdatePackage:
    return UpdatePackage(
        version=data["version"],
        package_type=data["package_type"],
        payload=bytes.fromhex(data["payload_hex"]),
        description=data["description"],
        published_at=data["published_at"],
        checksum_sha256=data["checksum_sha256"],
        signature=bytes.fromhex(data["signature_hex"]),
    )
