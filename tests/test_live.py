"""The live marker does not call AWS in this PR."""

import os

import pytest


@pytest.mark.live
def test_live_marker_runs_only_when_opted_in():
    assert os.environ.get("SV_LIVE") == "1"
