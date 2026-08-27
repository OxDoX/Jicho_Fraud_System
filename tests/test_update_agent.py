import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jicho.config import EngineConfig
from jicho.exceptions import UpdatePackageError
from jicho.update_agent import (
    UpdateAgent,
    UpdatePackage,
    compute_checksum,
    fetch_from_file,
    verify_package,
)


def _pem(private_key) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _make_package(private_key, payload: bytes, version="2026.01", package_type="config_update") -> UpdatePackage:
    return UpdatePackage(
        version=version,
        package_type=package_type,
        payload=payload,
        description="test package",
        published_at="2026-08-27T00:00:00Z",
        checksum_sha256=compute_checksum(payload),
        signature=private_key.sign(payload),
    )


@pytest.fixture
def vendor_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def agent(tmp_path, vendor_key):
    return UpdateAgent(
        public_key_pem=_pem(vendor_key),
        staging_dir=str(tmp_path / "staging"),
        state_dir=str(tmp_path / "state"),
    )


def test_verify_package_accepts_correctly_signed_package(vendor_key):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    package = _make_package(vendor_key, payload)
    verify_package(package, _pem(vendor_key))  # must not raise


def test_verify_package_rejects_tampered_payload(vendor_key):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    package = _make_package(vendor_key, payload)
    package.payload = json.dumps({"velocity_txn_count": 999}).encode()  # tampered after signing
    with pytest.raises(UpdatePackageError, match="Checksum mismatch"):
        verify_package(package, _pem(vendor_key))


def test_verify_package_rejects_malformed_public_key_with_a_typed_error(vendor_key):
    """A misconfigured public_key_pem (not this package's problem) must
    still surface as our own typed UpdatePackageError, not a raw
    cryptography-library ValueError — otherwise a deployment misconfig
    looks like an unhandled crash instead of a clear, actionable message.
    """
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    package = _make_package(vendor_key, payload)
    with pytest.raises(UpdatePackageError, match="not a valid PEM-encoded key"):
        verify_package(package, public_key_pem=b"not a real PEM key")


def test_verify_package_rejects_signature_from_wrong_key(vendor_key):
    attacker_key = Ed25519PrivateKey.generate()
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    package = _make_package(attacker_key, payload)  # signed by attacker, not the vendor
    with pytest.raises(UpdatePackageError, match="Signature verification failed"):
        verify_package(package, _pem(vendor_key))  # verified against the real vendor key


def test_pull_and_stage_never_raises_on_fetch_failure(agent):
    def broken_fetch():
        raise ConnectionError("cloud endpoint unreachable")

    result = agent.pull_and_stage(broken_fetch)  # must not raise
    assert result is None


def test_pull_and_stage_returns_none_when_no_update_available(agent):
    result = agent.pull_and_stage(lambda: None)
    assert result is None
    assert agent.list_staged() == []


def test_pull_and_stage_discards_invalid_package_without_staging(agent, vendor_key):
    attacker_key = Ed25519PrivateKey.generate()
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    bad_package = _make_package(attacker_key, payload)

    result = agent.pull_and_stage(lambda: bad_package)

    assert result is None
    assert agent.list_staged() == []  # a spoofed package must never reach staging


def test_pull_and_stage_stages_valid_package(agent, vendor_key):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    package = _make_package(vendor_key, payload)

    staged = agent.pull_and_stage(lambda: package)

    assert staged is not None
    assert staged.package.version == "2026.01"
    assert agent.list_staged() == ["2026.01.json"]


def test_promote_requires_named_reviewer(agent, vendor_key, tmp_path):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, payload))
    config_path = tmp_path / "config.yaml"

    with pytest.raises(ValueError, match="named reviewer"):
        agent.promote(staged, str(config_path), reviewer="", decision_note="looks fine")
    assert not config_path.exists()


def test_promote_writes_config_and_creates_rollback_backup(agent, vendor_key, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("velocity_txn_count: 4\nsim_swap_amount_threshold: 500000\n")

    payload = json.dumps({"velocity_txn_count": 6}).encode()
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, payload))
    agent.promote(staged, str(config_path), reviewer="jane@bank.co.tz", decision_note="approved after regression test")

    import yaml
    result = yaml.safe_load(config_path.read_text())
    assert result["velocity_txn_count"] == 6
    assert result["sim_swap_amount_threshold"] == 500000  # untouched keys preserved

    history_dir = tmp_path / "state" / "rollback_history"
    backups = list(history_dir.iterdir())
    assert len(backups) == 1
    assert "velocity_txn_count: 4" in backups[0].read_text()  # backup holds the PRE-promotion content


def test_rollback_restores_previous_config(agent, vendor_key, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("velocity_txn_count: 4\n")

    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, json.dumps({"velocity_txn_count": 6}).encode()))
    agent.promote(staged, str(config_path), reviewer="jane", decision_note="ok")
    assert "velocity_txn_count: 6" in config_path.read_text()

    agent.rollback(str(config_path))
    assert "velocity_txn_count: 4" in config_path.read_text()


def test_rollback_raises_when_no_history_available(agent, tmp_path):
    with pytest.raises(UpdatePackageError, match="No previous approved version"):
        agent.rollback(str(tmp_path / "config.yaml"))


def test_rollback_history_retains_only_last_three_versions(agent, vendor_key, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("velocity_txn_count: 1\n")

    for i in range(2, 7):  # 5 promotions -> should keep only the last 3 backups
        staged = agent.pull_and_stage(
            lambda i=i: _make_package(vendor_key, json.dumps({"velocity_txn_count": i}).encode(), version=f"2026.0{i}")
        )
        agent.promote(staged, str(config_path), reviewer="jane", decision_note=f"round {i}")

    history_dir = tmp_path / "state" / "rollback_history"
    assert len(list(history_dir.iterdir())) == 3


def test_promote_rejects_invalid_config_override_without_writing_or_backing_up(agent, vendor_key, tmp_path):
    """A typo'd/renamed config key must fail AT promotion time, pointing at
    the actual bad key — not silently write a config the engine will only
    reject the next time it starts. Also must not touch config_path or
    push a rollback backup for a promotion that never actually happened.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("velocity_txn_count: 4\n")

    bad_payload = json.dumps({"velocity_txn_cout": 6}).encode()  # typo'd key
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, bad_payload))

    with pytest.raises(UpdatePackageError, match="would be invalid"):
        agent.promote(staged, str(config_path), reviewer="jane", decision_note="typo, should fail")

    assert config_path.read_text() == "velocity_txn_count: 4\n"  # untouched
    history_dir = tmp_path / "state" / "rollback_history"
    assert not history_dir.exists() or list(history_dir.iterdir()) == []


def test_promote_rejects_non_config_update_package_type(agent, vendor_key, tmp_path):
    payload = b"def evaluate(self): pass"
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, payload, package_type="new_rule"))

    with pytest.raises(UpdatePackageError, match="manual code-review step"):
        agent.promote(staged, str(tmp_path / "config.yaml"), reviewer="jane", decision_note="n/a")


def test_reject_discards_staged_package(agent, vendor_key):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, payload))
    assert agent.list_staged() == ["2026.01.json"]

    agent.reject(staged, reviewer="jane", reason="false-positive risk too high without more data")

    assert agent.list_staged() == []


def test_health_check_false_when_never_pulled(agent):
    assert agent.health_check() is False


def test_health_check_true_after_recent_pull_attempt(agent):
    agent.pull_and_stage(lambda: None)  # even a "nothing new" pull counts as an attempt
    assert agent.health_check(max_days_since_last_pull=7) is True


def test_health_check_false_when_last_pull_too_old(agent, tmp_path):
    agent.pull_and_stage(lambda: None)
    stale_time = datetime.now(timezone.utc) - timedelta(days=10)
    (tmp_path / "state" / "last_pull_attempt").write_text(stale_time.isoformat())
    assert agent.health_check(max_days_since_last_pull=7) is False


def test_audit_log_records_every_step(agent, vendor_key, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("velocity_txn_count: 4\n")
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, json.dumps({"velocity_txn_count": 5}).encode()))
    agent.promote(staged, str(config_path), reviewer="jane", decision_note="ok")

    log_path = tmp_path / "state" / "audit_log.jsonl"
    events = [json.loads(line)["event"] for line in log_path.read_text().splitlines()]
    assert events == ["pull_verified", "staged", "promoted"]


def test_run_regression_test_reports_alert_count_diff(agent, vendor_key):
    import pandas as pd

    rows = []
    base = pd.Timestamp("2026-01-01 00:00:00")
    for i in range(5):
        rows.append({
            "transaction_id": f"T{i}", "account_id": "A1", "transaction_type": "withdrawal",
            "amount": 10_000, "timestamp": base + pd.Timedelta(minutes=i * 5), "channel": "mobile_money",
        })
    df = pd.DataFrame(rows)

    current_config = EngineConfig(velocity_txn_count=10)  # threshold too high to fire on 5 txns
    staged = agent.pull_and_stage(
        lambda: _make_package(vendor_key, json.dumps({"velocity_txn_count": 4}).encode())  # retuned to fire
    )

    result = agent.run_regression_test(staged, df, current_config)

    assert result.before_alert_count == 0
    assert result.after_alert_count >= 1
    assert result.after_by_rule.get("R2", 0) >= 1
    assert "R2" in result.summary()


def test_run_regression_test_rejects_non_config_update_package(agent, vendor_key):
    staged = agent.pull_and_stage(lambda: _make_package(vendor_key, b"code", package_type="new_rule"))
    with pytest.raises(UpdatePackageError, match="only implemented for config_update"):
        agent.run_regression_test(staged, None, EngineConfig())


def test_fetch_from_file_parses_manifest(tmp_path, vendor_key):
    payload = json.dumps({"velocity_txn_count": 5}).encode()
    manifest = {
        "version": "2026.03", "package_type": "config_update", "payload_hex": payload.hex(),
        "description": "quarterly threshold retune", "published_at": "2026-08-27T00:00:00Z",
        "checksum_sha256": compute_checksum(payload), "signature_hex": vendor_key.sign(payload).hex(),
    }
    manifest_path = tmp_path / "update.json"
    manifest_path.write_text(json.dumps(manifest))

    package = fetch_from_file(str(manifest_path))

    assert package.version == "2026.03"
    assert package.payload == payload
    verify_package(package, _pem(vendor_key))  # the round-tripped package must still verify
