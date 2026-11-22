from secbox.web import deception_actions


def test_list_deception_cases(
    monkeypatch,
):
    captured = {}

    def fake_exchange(request):
        captured.update(request)
        return {
            "case_count": 0,
            "cases": [],
        }

    monkeypatch.setattr(
        deception_actions,
        "_exchange",
        fake_exchange,
    )

    result = (
        deception_actions
        .list_deception_cases_via_helper()
    )

    assert captured == {
        "action": "get-deception-cases"
    }

    assert result["case_count"] == 0


def test_get_deception_case(
    monkeypatch,
):
    captured = {}

    def fake_exchange(request):
        captured.update(request)
        return {
            "case_id": "case-test",
        }

    monkeypatch.setattr(
        deception_actions,
        "_exchange",
        fake_exchange,
    )

    result = (
        deception_actions
        .get_deception_case_via_helper(
            case_id="case-test"
        )
    )

    assert captured == {
        "action": "get-deception-case",
        "case_id": "case-test",
    }

    assert result["case_id"] == "case-test"


def test_list_deception_quarantine(
    monkeypatch,
):
    captured = {}

    def fake_exchange(request):
        captured.update(request)

        return {
            "quarantine_count": 0,
            "quarantine": [],
        }

    monkeypatch.setattr(
        deception_actions,
        "_exchange",
        fake_exchange,
    )

    result = (
        deception_actions
        .list_deception_quarantine_via_helper()
    )

    assert captured == {
        "action":
            "get-deception-quarantine"
    }

    assert (
        result["quarantine_count"]
        == 0
    )


def test_release_deception_quarantine(
    monkeypatch,
):
    captured = {}

    def fake_exchange(request):
        captured.update(request)

        return {
            "status": "released",
            "case_id": "case-test",
        }

    monkeypatch.setattr(
        deception_actions,
        "_exchange",
        fake_exchange,
    )

    result = (
        deception_actions
        .release_deception_quarantine_via_helper(
            case_id="case-test"
        )
    )

    assert captured == {
        "action":
            "release-deception-quarantine",
        "case_id":
            "case-test",
    }

    assert result["status"] == "released"
