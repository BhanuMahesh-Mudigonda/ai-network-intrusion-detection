"""
Unit Tests for FastAPI Real-Time Prediction API.

Validates:
1. GET /
2. GET /health
3. GET /model-info
4. POST /predict schema validation (rejection of missing features, NaN, Inf, non-numeric)
5. POST /predict successful prediction with exact required JSON output format
"""

import sys
import math
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from api.main import app
from api.schemas import FEATURE_NAMES
from api.model_service import model_service


@pytest.fixture
def client():
    """Test client fixture with lifespan context manager enabled."""
    with TestClient(app) as c:
        yield c


def get_valid_sample_payload():
    """Generates a valid 78-feature sample payload."""
    payload = {}
    for name in FEATURE_NAMES:
        payload[name] = 1.0
    payload["Destination Port"] = 80.0
    payload["Flow Duration"] = 12000.0
    payload["Total Fwd Packets"] = 5.0
    payload["Total Backward Packets"] = 3.0
    return payload


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Network Intrusion Detection API"
    assert data["status"] == "online"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["features_expected"] == 78


def test_model_info_endpoint(client):
    response = client.get("/model-info")
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "XGBoost"
    assert data["num_features"] == 78
    assert data["num_classes"] == 15
    assert data["audit_status"] == "VALID WITH CAUTION"


def test_predict_missing_required_feature(client):
    """Test POST /predict rejects payload missing required features (returns 422)."""
    payload = get_valid_sample_payload()
    del payload["Destination Port"]

    response = client.post("/predict", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "Validation Error" in data["error"] or "detail" in data


def test_predict_nan_value_rejection(client):
    """Test POST /predict rejects NaN values (returns 422)."""
    payload = get_valid_sample_payload()
    payload["Flow Bytes/s"] = "NaN"

    response = client.post("/predict", json=payload)
    assert response.status_code == 422


def test_predict_infinite_value_rejection(client):
    """Test POST /predict rejects +Inf / -Inf values (returns 422)."""
    payload = get_valid_sample_payload()
    payload["Flow Packets/s"] = "Infinity"

    response = client.post("/predict", json=payload)
    assert response.status_code == 422


def test_predict_invalid_data_type(client):
    """Test POST /predict rejects non-numeric string values (returns 422)."""
    payload = get_valid_sample_payload()
    payload["Destination Port"] = "invalid_string_port"

    response = client.post("/predict", json=payload)
    assert response.status_code == 422


def test_predict_valid_payload(client):
    """Test POST /predict returns required prediction structure when model is loaded."""
    payload = get_valid_sample_payload()
    response = client.post("/predict", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "prediction" in data
    assert "prediction_label" in data
    assert "confidence" in data
    assert "attack_probability" in data
    assert "normal_probability" in data
    assert 0.0 <= data["confidence"] <= 1.0
    assert 0.0 <= data["attack_probability"] <= 1.0
    assert 0.0 <= data["normal_probability"] <= 1.0


if __name__ == "__main__":
    pytest.main(["-v", __file__])
