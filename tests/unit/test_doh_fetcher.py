import pytest

from secbox.modules.content_filter.doh_feed import fetcher


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        content_length: str | None = None,
    ):
        self.payload = payload
        self.headers = {}

        if content_length is not None:
            self.headers["Content-Length"] = (
                content_length
            )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        return self.payload[:size]


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        return self.response


def patch_response(
    monkeypatch,
    response,
):
    monkeypatch.setattr(
        fetcher.urllib.request,
        "build_opener",
        lambda *handlers: FakeOpener(response),
    )


def test_fetch_feed(monkeypatch) -> None:
    patch_response(
        monkeypatch,
        FakeResponse(
            b"1.1.1.1\n8.8.8.8\n"        ),
    )

    result = fetcher.fetch_doh_feed(
        "https://example.test/feed.txt"
    )

    assert result == "1.1.1.1\n8.8.8.8\n"


def test_fetch_rejects_large_payload(
    monkeypatch,
) -> None:
    patch_response(
        monkeypatch,
        FakeResponse(
            b"x" * 11,        ),
    )

    with pytest.raises(
        fetcher.DohFeedFetchError,
        match="exceeds maximum size",
    ):
        fetcher.fetch_doh_feed(
            "https://example.test/feed.txt",
            max_bytes=10,
        )


def test_fetch_rejects_large_content_length(
    monkeypatch,
) -> None:
    patch_response(
        monkeypatch,
        FakeResponse(
            b"",
            content_length="1000",        ),
    )

    with pytest.raises(
        fetcher.DohFeedFetchError,
        match="exceeds maximum size",
    ):
        fetcher.fetch_doh_feed(
            "https://example.test/feed.txt",
            max_bytes=100,
        )


def test_fetch_rejects_invalid_utf8(
    monkeypatch,
) -> None:
    patch_response(
        monkeypatch,
        FakeResponse(
            b"\xff\xfe\xfd"        ),
    )

    with pytest.raises(
        fetcher.DohFeedFetchError,
        match="not valid UTF-8",
    ):
        fetcher.fetch_doh_feed(
            "https://example.test/feed.txt"
        )


def test_redirect_handler_rejects_http() -> None:
    handler = fetcher.HttpsOnlyRedirectHandler()

    with pytest.raises(
        fetcher.DohFeedFetchError,
        match="redirect must use HTTPS",
    ):
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "http://example.test/feed.txt",
        )
