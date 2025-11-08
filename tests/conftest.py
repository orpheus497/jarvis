"""
Pytest configuration and fixtures for Jarvis Messenger tests.

Created by orpheus497

Provides common fixtures and test utilities for unit and integration tests.
"""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test data.

    Yields:
        Path: Temporary directory path

    Cleanup:
        Automatically removes directory after test
    """
    tmp = Path(tempfile.mkdtemp(prefix="jarvis_test_"))
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir: Path) -> Generator[Path, None, None]:
    """
    Create a temporary file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Yields:
        Path: Temporary file path
    """
    file_path = temp_dir / "test_file.txt"
    file_path.touch()
    yield file_path


@pytest.fixture
def sample_identity_data() -> dict:
    """
    Provide sample identity data for testing.

    Returns:
        dict: Sample identity dictionary
    """
    return {
        'uid': 'a' * 32,
        'username': 'test_user',
        'created_at': '2025-01-01T00:00:00+00:00',
        'fingerprint': 'b' * 64,
        'listen_port': 5000,
        'keypair': {
            'private_key': 'c' * 64,
            'public_key': 'd' * 64
        }
    }


@pytest.fixture
def sample_contact_data() -> dict:
    """
    Provide sample contact data for testing.

    Returns:
        dict: Sample contact dictionary
    """
    return {
        'uid': 'e' * 32,
        'username': 'contact_user',
        'public_key': 'f' * 64,
        'fingerprint': 'g' * 64,
        'ip_address': '192.168.1.100',
        'port': 5000,
        'added_at': '2025-01-01T00:00:00+00:00',
        'last_seen': '2025-01-01T00:00:00+00:00',
        'online': False
    }


@pytest.fixture
def sample_message_data() -> dict:
    """
    Provide sample message data for testing.

    Returns:
        dict: Sample message dictionary
    """
    return {
        'message_id': 'h' * 32,
        'contact_uid': 'e' * 32,
        'content': 'Hello, World!',
        'timestamp': '2025-01-01T00:00:00+00:00',
        'sent_by_me': True,
        'read': False,
        'encrypted': True
    }


@pytest.fixture
def sample_group_data() -> dict:
    """
    Provide sample group data for testing.

    Returns:
        dict: Sample group dictionary
    """
    return {
        'group_id': 'i' * 32,
        'name': 'Test Group',
        'created_at': '2025-01-01T00:00:00+00:00',
        'created_by': 'a' * 32,
        'members': []
    }


# Pytest marks
def pytest_configure(config):
    """
    Configure pytest markers.

    Args:
        config: Pytest configuration object
    """
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


# Test collection hooks
def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to add markers based on test location.

    Args:
        config: Pytest configuration
        items: List of collected test items
    """
    for item in items:
        # Add unit marker to tests in unit/ directory
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)

        # Add integration marker to tests in integration/ directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
