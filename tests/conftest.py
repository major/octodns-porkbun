from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from oinker.dns import DNSRecordResponse


@pytest.fixture
def mock_piglet() -> MagicMock:
    """Mock Piglet client with context manager support."""
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=None)
    return mock


@pytest.fixture
def api_credentials() -> dict[str, str]:
    return {"api_key": "pk1_test_key", "secret_key": "sk1_test_secret"}


def make_dns_response(
    id: str,
    name: str,
    record_type: str,
    content: str,
    ttl: int = 600,
    priority: int = 0,
) -> DNSRecordResponse:
    return DNSRecordResponse(
        id=id,
        name=name,
        record_type=record_type,
        content=content,
        ttl=ttl,
        priority=priority,
    )
