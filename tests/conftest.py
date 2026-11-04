import os
import socket

import pytest

os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


class _BlockedSocket:
    def __init__(self, *args, **kwargs):
        raise AssertionError("network access is blocked in tests")


def _blocked_connection(*args, **kwargs):
    raise AssertionError("network access is blocked in tests")


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """No test may open a socket. Moto and Stubber stay in process."""

    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", _blocked_connection)


def pytest_collection_modifyitems(config, items):
    if os.environ.get("SV_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="live AWS test; set SV_LIVE=1 to run it")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)
