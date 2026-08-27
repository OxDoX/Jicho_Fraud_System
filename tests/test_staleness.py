import os
import time

from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ScopeAsset, ScopeDoc
from sentinel.phases import phase1_5_threat_intel as ti


def _scope():
    return ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )


def test_no_brief_on_file_warns(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    assert ti.brief_age_days(eng) is None
    warning = ti.staleness_warning(eng)
    assert warning is not None
    assert "no Phase 1.5 threat-intel brief" in warning


def test_fresh_brief_has_no_warning(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    ti.brief_path(eng).write_text("brief content")

    assert ti.staleness_warning(eng) is None
    assert ti.brief_age_days(eng) < 1


def test_old_brief_warns_stale(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    path = ti.brief_path(eng)
    path.write_text("old brief")
    old_time = time.time() - (ti.STALE_AFTER_DAYS + 1) * 86400
    os.utime(path, (old_time, old_time))

    warning = ti.staleness_warning(eng)
    assert warning is not None
    assert "days old" in warning
