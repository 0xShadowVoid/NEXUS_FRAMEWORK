"""Unit and integration tests for NEXUS Pass 7 GUI and secure remote operations."""

import os

from fastapi.testclient import TestClient

from core.gui import app

from lib.config import Config

from core.database import Database

client = TestClient(app)

def test_gui_health():

    response = client.get("/health")

    assert response.status_code == 200

    assert response.json()["status"] == "healthy"

def test_gui_unconfigured_credentials_fail_closed():

    # Without NEXUS_GUI_USER and NEXUS_GUI_PASS set, GUI should fail closed with 503

    os.environ.pop("NEXUS_GUI_USER", None)

    os.environ.pop("NEXUS_GUI_PASS", None)

    response = client.get("/", auth=("any_user", "any_pass"))

    assert response.status_code == 503

    assert "credentials not configured" in response.json()["detail"]

def test_gui_authenticated_dashboard():

    os.environ["NEXUS_GUI_USER"] = "test_operator"

    os.environ["NEXUS_GUI_PASS"] = "secure_test_pass!"

    # Test with correct credentials

    response = client.get("/", auth=("test_operator", "secure_test_pass!"))

    assert response.status_code == 200

    assert "NEXUS Security Framework" in response.text

    # Test with incorrect credentials

    response_bad = client.get("/", auth=("test_operator", "wrong_pass"))

    assert response_bad.status_code == 401

    # Clean up env

    os.environ.pop("NEXUS_GUI_USER", None)

    os.environ.pop("NEXUS_GUI_PASS", None)

def test_gui_api_engagements():

    os.environ["NEXUS_GUI_USER"] = "nexus_operator"

    os.environ["NEXUS_GUI_PASS"] = "secure_nexus_2026!"

    response = client.get("/api/engagements", auth=("nexus_operator", "secure_nexus_2026!"))

    assert response.status_code == 200

    assert "engagements" in response.json()

    os.environ.pop("NEXUS_GUI_USER", None)

    os.environ.pop("NEXUS_GUI_PASS", None)

def test_gui_scan_requires_confirmation():

    os.environ["NEXUS_GUI_USER"] = "nexus_operator"

    os.environ["NEXUS_GUI_PASS"] = "secure_nexus_2026!"

    response = client.post(

        "/api/scan",

        json={"target": "example.com", "intensity": "quick-scan", "confirm": False},

        auth=("nexus_operator", "secure_nexus_2026!")

    )

    assert response.status_code == 400

    assert "Explicit confirmation required" in response.json()["detail"]

    os.environ.pop("NEXUS_GUI_USER", None)

    os.environ.pop("NEXUS_GUI_PASS", None)

def test_gui_scope_validation_enforcement():

    os.environ["NEXUS_GUI_USER"] = "nexus_operator"

    os.environ["NEXUS_GUI_PASS"] = "secure_nexus_2026!"

    # A target that is not part of the configured scope must be rejected by the
    # server-side scope validator (which derives its boundary only from the
    # configured `targets:` scope, never from the request).

    response = client.post(

        "/api/scan",

        json={"target": "not-a-configured-target.example", "intensity": "quick-scan", "confirm": True},

        auth=("nexus_operator", "secure_nexus_2026!")

    )

    # Scope validation raises error -> 403 Forbidden

    assert response.status_code == 403

    os.environ.pop("NEXUS_GUI_USER", None)

    os.environ.pop("NEXUS_GUI_PASS", None)