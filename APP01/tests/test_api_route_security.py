import inspect

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import identity_requests


TEST_KEYS = {
    "IAM_VIEWER_API_KEY": "test-viewer-key",
    "IAM_SYNC_API_KEY": "test-sync-key",
    "IAM_APPROVER_API_KEY": "test-approver-key",
    "IAM_PROVISIONER_API_KEY": "test-provisioner-key",
    "IAM_ADMIN_API_KEY": "test-admin-key",
}


@pytest.fixture
def client(monkeypatch):
    for variable, value in TEST_KEYS.items():
        monkeypatch.setenv(variable, value)

    with TestClient(app) as test_client:
        yield test_client


def api_header(key_name):
    return {
        "X-API-Key": TEST_KEYS[key_name],
    }


def test_root_endpoint_remains_public(client):
    response = client.get("/")

    assert response.status_code == 200


def test_protected_endpoint_rejects_missing_key(client):
    response = client.get("/oauth/status")

    assert response.status_code == 401


def test_viewer_can_access_read_endpoint(client):
    response = client.get(
        "/oauth/status",
        headers=api_header("IAM_VIEWER_API_KEY"),
    )

    assert response.status_code == 200


def test_viewer_cannot_run_hr_sync(client):
    response = client.post(
        "/sync/employees",
        headers=api_header("IAM_VIEWER_API_KEY"),
        json={},
    )

    assert response.status_code == 403


def test_viewer_cannot_approve_request(client):
    response = client.post(
        "/identity-requests/TEST-NOT-FOUND/approve",
        headers=api_header("IAM_VIEWER_API_KEY"),
        json={},
    )

    assert response.status_code == 403


def test_approver_cannot_provision_request(client):
    response = client.post(
        "/identity-requests/TEST-NOT-FOUND/provision",
        headers=api_header("IAM_APPROVER_API_KEY"),
        json={},
    )

    assert response.status_code == 403


def test_provisioner_cannot_approve_request(client):
    response = client.post(
        "/identity-requests/TEST-NOT-FOUND/approve",
        headers=api_header("IAM_PROVISIONER_API_KEY"),
        json={},
    )

    assert response.status_code == 403


def test_actor_identity_comes_from_authenticated_principal():
    approve_source = inspect.getsource(
        identity_requests.approve_identity_request
    )

    reject_source = inspect.getsource(
        identity_requests.reject_identity_request
    )

    assert "approver = principal.subject" in approve_source
    assert "approval.approved_by.strip()" not in approve_source

    assert "rejected_by = principal.subject" in reject_source
    assert "rejection.rejected_by.strip()" not in reject_source
