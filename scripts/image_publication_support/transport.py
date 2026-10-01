"""Bounded HTTPS metadata transport with credential-safe redirects."""

import json
import urllib.error
import urllib.parse
import urllib.request

from .policy import require


class PublicationRedirects(urllib.request.HTTPRedirectHandler):
    """Keep registry credentials on the same HTTPS origin during redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before = urllib.parse.urlsplit(req.full_url)
        after = urllib.parse.urlsplit(newurl)
        if after.scheme != "https" or after.netloc != before.netloc:
            raise urllib.error.URLError(
                "Publication metadata redirected outside its origin"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_json(url: str, headers: dict[str, str]) -> tuple[int, dict]:
    """Read bounded official metadata without including response bodies in errors."""
    request = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.build_opener(PublicationRedirects()).open(
            request, timeout=30
        )
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(1024 * 1024 + 1)
        require(len(body) <= 1024 * 1024, "Publication metadata exceeds the size limit")
        result = json.loads(body)
        require(isinstance(result, dict), "Publication metadata must be a JSON object")
        return response.code, result
