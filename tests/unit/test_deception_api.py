from fastapi import FastAPI
from fastapi.testclient import TestClient

from secbox.web import deception_api


def make_client():
    app = FastAPI()
    app.include_router(
        deception_api.router
    )
    return TestClient(app)


def test_cases_endpoint(
    monkeypatch,
):
    monkeypatch.setattr(
        deception_api,
        "list_deception_cases_via_helper",
        lambda: {
            "case_count": 1,
            "cases": [
                {
                    "case_id": "case-test",
                }
            ],
        },
    )

    response = make_client().get(
        "/api/v1/deception/cases"
    )

    assert response.status_code == 200
    assert response.json()["case_count"] == 1


def test_case_endpoint(
    monkeypatch,
):
    monkeypatch.setattr(
        deception_api,
        "get_deception_case_via_helper",
        lambda *, case_id: {
            "case_id": case_id,
            "telemetry": {
                "event_count": 4,
            },
        },
    )

    response = make_client().get(
        "/api/v1/deception/cases/case-test"
    )

    assert response.status_code == 200
    assert (
        response.json()["telemetry"]["event_count"]
        == 4
    )


def test_quarantine_endpoint(
    monkeypatch,
):
    monkeypatch.setattr(
        deception_api,
        "list_deception_quarantine_via_helper",
        lambda: {
            "quarantine_count": 1,
            "quarantine": [
                {
                    "case_id":
                        "case-test",
                    "source_ip":
                        "198.18.0.60",
                }
            ],
        },
    )

    response = make_client().get(
        "/api/v1/deception/quarantine"
    )

    assert response.status_code == 200

    assert (
        response.json()[
            "quarantine_count"
        ]
        == 1
    )


def test_release_quarantine_endpoint(
    monkeypatch,
):
    monkeypatch.setattr(
        deception_api,
        "release_deception_quarantine_via_helper",
        lambda *, case_id: {
            "status": "released",
            "case_id": case_id,
            "source_ip":
                "198.18.0.60",
        },
    )

    response = make_client().post(
        "/api/v1/deception/quarantine/"
        "case-test/release"
    )

    assert response.status_code == 200

    assert (
        response.json()["status"]
        == "released"
    )
