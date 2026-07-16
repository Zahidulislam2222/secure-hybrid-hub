from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import urllib.parse
import urllib.robotparser
from html.parser import HTMLParser


ALLOWED_MEDIA = {"text/plain", "text/html", "application/json", "application/xml", "text/xml"}


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "noscript"}:
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript"} and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored:
            text = " ".join(data.split())
            if text:
                self.parts.append(text)

    def text(self) -> str:
        return "\n".join(self.parts)


def validate_url(url: str, domains: set[str]) -> urllib.parse.SplitResult:
    if len(url.encode("utf-8")) > 4096:
        raise ValueError("URL exceeds limit")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("only credential-free HTTPS URLs without fragments are allowed")
    if not parsed.hostname or parsed.port not in {None, 443}:
        raise ValueError("research URL host or port is invalid")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if hostname not in domains:
        raise ValueError("research URL host is not explicitly approved")
    return parsed


def resolve_public(hostname: str) -> list[str]:
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError("research host did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("research host resolved to a forbidden address")
    return addresses


def request_once(url: str, domains: set[str], timeout: int, maximum: int, user_agent: str):
    parsed = validate_url(url, domains)
    hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    addresses = resolve_public(hostname)
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for address in addresses:
        connection = http.client.HTTPSConnection(hostname, 443, timeout=timeout, context=context)
        try:
            raw_socket = socket.create_connection((address, 443), timeout=timeout)
            connection.sock = context.wrap_socket(raw_socket, server_hostname=hostname)
            target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            connection.request("GET", target, headers={"User-Agent": user_agent, "Accept": "text/html,text/plain,application/json,application/xml;q=0.8", "Accept-Encoding": "identity", "Connection": "close"})
            response = connection.getresponse()
            encoding = response.getheader("Content-Encoding", "identity").lower()
            if encoding not in {"", "identity"}:
                raise ValueError("compressed research responses are rejected")
            length = response.getheader("Content-Length")
            if length and int(length) > maximum:
                raise ValueError("research response exceeds size limit")
            content = response.read(maximum + 1)
            if len(content) > maximum:
                raise ValueError("research response exceeds size limit")
            return response.status, dict(response.getheaders()), content
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise ValueError(f"research connection failed: {type(last_error).__name__ if last_error else 'unknown'}")


def robots_allowed(url: str, domains: set[str], timeout: int, user_agent: str) -> bool:
    parsed = validate_url(url, domains)
    robots_url = urllib.parse.urlunsplit(("https", parsed.netloc, "/robots.txt", "", ""))
    status, headers, content = request_once(robots_url, domains, timeout, 256 * 1024, user_agent)
    if status in {401, 403}:
        return False
    if status == 404:
        return True
    if status < 200 or status >= 300:
        raise ValueError(f"robots.txt returned HTTP {status}")
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(content.decode("utf-8", errors="replace").splitlines())
    return parser.can_fetch(user_agent, url)


def fetch(url: str, domains: set[str], timeout: int, maximum: int, user_agent: str) -> dict:
    if not robots_allowed(url, domains, timeout, user_agent):
        raise ValueError("robots policy denies the research URL")
    current = url
    redirects: list[str] = []
    for _ in range(4):
        status, headers, content = request_once(current, domains, timeout, maximum, user_agent)
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("Location") or headers.get("location")
            if not location:
                raise ValueError("research redirect omitted Location")
            current = urllib.parse.urljoin(current, location)
            validate_url(current, domains)
            redirects.append(current)
            continue
        if status < 200 or status >= 300:
            raise ValueError(f"research server returned HTTP {status}")
        media_type = (headers.get("Content-Type") or headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if media_type not in ALLOWED_MEDIA:
            raise ValueError("research response MIME type is not approved")
        text = content.decode("utf-8", errors="strict")
        if media_type == "text/html":
            extractor = TextExtractor()
            extractor.feed(text)
            text = extractor.text()
        normalized = "\n".join(line.strip() for line in text.splitlines() if line.strip())
        if len(normalized.encode("utf-8")) > maximum:
            raise ValueError("normalized research content exceeds size limit")
        return {"source_url": current, "redirects": redirects, "media_type": media_type, "raw_hash": hashlib.sha256(content).hexdigest(), "content": normalized, "size": len(normalized.encode("utf-8")), "robots_checked": True}
    raise ValueError("research redirect limit exceeded")


def discover_searxng(query: str, domains: set[str], limit: int, timeout: int) -> dict:
    if not isinstance(query, str) or not query.strip() or len(query.encode("utf-8")) > 2048:
        raise ValueError("SearXNG query is invalid")
    connection = http.client.HTTPConnection("127.0.0.1", 8888, timeout=timeout)
    try:
        target = "/search?" + urllib.parse.urlencode({"q": query, "format": "json", "safesearch": 1})
        connection.request("GET", target, headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"SearXNG returned HTTP {response.status}")
        if (response.getheader("Content-Type") or "").split(";", 1)[0].lower() != "application/json":
            raise ValueError("SearXNG returned an invalid MIME type")
        raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError("SearXNG response exceeds limit")
        payload = json.loads(raw)
    finally:
        connection.close()
    results = []
    for item in payload.get("results", []):
        if len(results) >= limit or not isinstance(item, dict) or not isinstance(item.get("url"), str):
            continue
        try:
            parsed = validate_url(item["url"], domains)
        except ValueError:
            continue
        title = " ".join(str(item.get("title", "")).split())[:300]
        results.append({"url": urllib.parse.urlunsplit(parsed), "title": title, "untrusted_discovery": True})
    return {"results": results, "count": len(results), "endpoint": "http://127.0.0.1:8888", "content_fetched": False}


def main() -> int:
    request = json.loads(open("input.json", encoding="utf-8").read())
    if request.get("mode", "fetch") == "discover":
        result = discover_searxng(request["query"], set(request["domains"]), request["limit"], request["timeout"])
    else:
        result = fetch(request["url"], set(request["domains"]), request["timeout"], request["max_bytes"], request["user_agent"])
    print(json.dumps({"ok": True, "result": result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, sort_keys=True, separators=(",", ":")))
        raise SystemExit(2)
