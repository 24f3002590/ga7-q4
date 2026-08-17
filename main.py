import html
import json
import re
from urllib.parse import unquote, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-ii3v6se.example",
    "app-teee7zh.example",
}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# Exact required entity set.
ENTITY_RE = re.compile(
    r"&(?:lt|gt|quot|apos|amp);|&#(?:[0-9]+);|&#x[0-9a-fA-F]+;",
    re.IGNORECASE,
)

UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")

DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_RE = re.compile(
    r"\bon[A-Za-z0-9_-]*\s*=",
    re.IGNORECASE,
)

# Only quoted src/href values are URL candidates for HTML.
HTML_URL_RE = re.compile(
    r"""\b(?:src|href)\s*=\s*(["'])(.*?)\1""",
    re.IGNORECASE | re.DOTALL,
)

# Target inside ](...)
MARKDOWN_URL_RE = re.compile(
    r"""\]\(\s*([^\s)]*).*?\)""",
    re.DOTALL,
)

SQL_META_RE = re.compile(
    r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
    re.IGNORECASE,
)

SHELL_META_RE = re.compile(
    r"""[;&|`<>]|\$\(|\$\{"""
)


def decode_entities_once(value: str) -> str:
    """Decode only the entities explicitly specified by the task."""

    def repl(match: re.Match) -> str:
        token = match.group(0)

        if token.lower() == "&lt;":
            return "<"
        if token.lower() == "&gt;":
            return ">"
        if token.lower() == "&quot;":
            return '"'
        if token.lower() == "&apos;":
            return "'"
        if token.lower() == "&amp;":
            return "&"

        body = token[2:-1]

        try:
            if body.lower().startswith("#x"):
                return chr(int(body[2:], 16))
            if body.startswith("#"):
                return chr(int(body[1:], 10))
        except (ValueError, OverflowError):
            pass

        return token

    return ENTITY_RE.sub(repl, value)


def decode_unicode_once(value: str) -> str:
    def repl(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return UNICODE_ESCAPE_RE.sub(repl, value)


def decode_once(value: str) -> str:
    # Required order:
    # percent escapes -> HTML entities -> \uXXXX
    value = unquote(value)
    value = decode_entities_once(value)
    value = decode_unicode_once(value)
    return value


def extracted_urls(channel: str, output: str) -> list[str]:
    if channel == "html":
        return [m.group(2) for m in HTML_URL_RE.finditer(output)]

    if channel == "markdown":
        return [m.group(1) for m in MARKDOWN_URL_RE.finditer(output)]

    if channel == "url":
        return [output.strip()]

    return []


def has_dangerous_scheme(channel: str, output: str) -> bool:
    # Explicit dangerous schemes anywhere in the relevant output.
    if DANGEROUS_SCHEME_RE.search(output):
        return True

    # Extracted URLs must use http/https if they have a scheme.
    for raw in extracted_urls(channel, output):
        value = raw.strip()

        if not value:
            continue

        # Protocol-relative URLs are resolved as HTTPS.
        parse_value = "https:" + value if value.startswith("//") else value

        try:
            parsed = urlsplit(parse_value)
        except ValueError:
            # A malformed URL containing a scheme should not be accepted.
            if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*\s*:", value):
                return True
            continue

        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return True

    return False


def has_external_exfil(channel: str, output: str) -> bool:
    for raw in extracted_urls(channel, output):
        value = raw.strip()

        if not value:
            continue

        # Relative references are explicitly allowed.
        is_protocol_relative = value.startswith("//")

        if is_protocol_relative:
            parse_value = "https:" + value
        else:
            parse_value = value

        try:
            parsed = urlsplit(parse_value)
        except ValueError:
            continue

        # Absolute URL:
        #   http://...
        #   https://...
        #   //...
        absolute = bool(parsed.scheme) or is_protocol_relative

        if not absolute:
            continue

        # Compare hostname only.
        hostname = parsed.hostname

        if hostname is None:
            return True

        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


def evaluate(channel: str, output: str) -> str:
    # Channel-specific rules, in exact order.
    if channel == "html":
        if SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"

        if EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "markdown":
        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "url":
        if has_dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "sql":
        return "SQL_METACHAR" if SQL_META_RE.search(output) else "SAFE"

    if channel == "shell":
        return "SHELL_METACHAR" if SHELL_META_RE.search(output) else "SAFE"

    return "INVALID_SCHEMA"


def make_response(reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        },
    )


@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    # Manual parsing gives deterministic JSON behavior instead of FastAPI's
    # automatic 422 schema responses.
    try:
        body = await request.json()
    except Exception:
        return make_response("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return make_response("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if (
        channel not in CHANNELS
        or not isinstance(output, str)
        or len(output) > 20000
    ):
        return make_response("INVALID_SCHEMA")

    # Rule 2: decode exactly once.
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = evaluate(channel, decoded)

        if decoded_reason != "SAFE":
            return make_response("ENCODED_PAYLOAD")

    # Rule 3: evaluate original output.
    return make_response(evaluate(channel, output))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
