"""HTTPS downloader for managed DoH resolver feeds."""

import urllib.error
import urllib.request


class DohFeedFetchError(Exception):
    """Raised when a managed DoH feed cannot be downloaded."""


class HttpsOnlyRedirectHandler(
    urllib.request.HTTPRedirectHandler
):
    """Reject redirects from HTTPS to non-HTTPS URLs."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        if not newurl.lower().startswith("https://"):
            raise DohFeedFetchError(
                "DoH feed redirect must use HTTPS"
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


def fetch_doh_feed(
    url: str,
    *,
    timeout_seconds: int = 10,
    max_bytes: int = 1048576,
) -> str:
    """Download a bounded UTF-8 DoH resolver feed."""

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SecBox-DoH-Feed/1",
            "Accept": "text/plain",
        },
        method="GET",
    )

    try:
        opener = urllib.request.build_opener(
            HttpsOnlyRedirectHandler()
        )

        with opener.open(
            request,
            timeout=timeout_seconds,
        ) as response:
            content_length = response.headers.get(
                "Content-Length"
            )

            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    declared_size = None

                if (
                    declared_size is not None
                    and declared_size > max_bytes
                ):
                    raise DohFeedFetchError(
                        "DoH feed exceeds maximum size"
                    )

            payload = response.read(
                max_bytes + 1
            )

    except DohFeedFetchError:
        raise

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as error:
        raise DohFeedFetchError(
            f"failed to download DoH feed: {error}"
        ) from error

    if len(payload) > max_bytes:
        raise DohFeedFetchError(
            "DoH feed exceeds maximum size"
        )

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DohFeedFetchError(
            "DoH feed is not valid UTF-8"
        ) from error
