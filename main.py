import json
import re
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-ii3v6se.example",
    "app-teee7zh.example",
}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}


# ------------------------------------------------------------
# Schema
# ------------------------------------------------------------

def result(reason: str):
    return JSONResponse(
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        },
        status_code=200,
    )


# ------------------------------------------------------------
# EXACT one-pass decoding
#
# percent escapes -> HTML entities -> \uXXXX
# ------------------------------------------------------------

PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")

ENTITY_RE = re.compile(
    r"""
    &(?:
        lt|gt|quot|apos|amp
        |
        \#[0-9]+
        |
        \#x[0-9A-Fa-f]+
    );
    """,
    re.IGNORECASE | re.VERBOSE,
)

UNICODE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")


def decode_percent_once(s: str) -> str:
    """
    Decode valid %XX escapes once.

    Do not recursively decode.
    Do not turn malformed percent sequences into replacement chars.
    """

    def repl(m):
        return chr(int(m.group(1), 16))

    return PERCENT_RE.sub(repl, s)


def decode_entities_once(s: str) -> str:
    def repl(m):
        token = m.group(0).lower()

        if token == "&lt;":
            return "<"
        if token == "&gt;":
            return ">"
        if token == "&quot;":
            return '"'
        if token == "&apos;":
            return "'"
        if token == "&amp;":
            return "&"

        body = token[2:-1]

        try:
            if body.startswith("#x"):
                return chr(int(body[2:], 16))
            if body.startswith("#"):
                return chr(int(body[1:], 10))
        except (ValueError, OverflowError):
            pass

        return m.group(0)

    return ENTITY_RE.sub(repl, s)


def decode_unicode_once(s: str) -> str:
    def repl(m):
        return chr(int(m.group(1), 16))

    return UNICODE_RE.sub(repl, s)


def decode_once(s: str) -> str:
    s = decode_percent_once(s)
    s = decode_entities_once(s)
    s = decode_unicode_once(s)
    return s


# ------------------------------------------------------------
# URL extraction
# ------------------------------------------------------------

HTML_ATTR_RE = re.compile(
    r"""
    \b(?:src|href)
    \s*=\s*
    (?:
        "([^"]*)"
        |
        '([^']*)'
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

MARKDOWN_TARGET_RE = re.compile(
    r"""
    \]\(
    \s*
    (
        (?:
            <[^>]*>
            |
            [^)\s]+
        )
    )
    """,
    re.VERBOSE | re.DOTALL,
)


def extract_urls(channel: str, output: str):
    if channel == "html":
        urls = []
        for m in HTML_ATTR_RE.finditer(output):
            urls.append(m.group(1) if m.group(1) is not None else m.group(2))
        return urls

    if channel == "markdown":
        urls = []
        for m in MARKDOWN_TARGET_RE.finditer(output):
            value = m.group(1)

            # Markdown permits <url> targets.
            if value.startswith("<") and value.endswith(">"):
                value = value[1:-1]

            urls.append(value)

        return urls

    if channel == "url":
        return [output.strip()]

    return []


# ------------------------------------------------------------
# Dangerous schemes
# ------------------------------------------------------------

DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

ANY_SCHEME_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*\s*:"
)


def dangerous_scheme(channel: str, output: str) -> bool:
    # Explicit dangerous schemes anywhere in the text.
    if DANGEROUS_SCHEME_RE.search(output):
        return True

    # Every extracted URL must either be relative or use HTTP(S).
    for raw in extract_urls(channel, output):
        value = raw.strip()

        if not value:
            continue

        # Protocol-relative is explicitly HTTPS for this task.
        candidate = "https:" + value if value.startswith("//") else value

        try:
            parsed = urlsplit(candidate)
        except ValueError:
            # If it visibly has a scheme, it is not a permitted one.
            if ANY_SCHEME_RE.match(value):
                return True
            continue

        if parsed.scheme:
            if parsed.scheme.lower() not in ("http", "https"):
                return True

    return False


# ------------------------------------------------------------
# External exfiltration
# ------------------------------------------------------------

def external_exfil(channel: str, output: str) -> bool:
    for raw in extract_urls(channel, output):
        value = raw.strip()

        if not value:
            continue

        protocol_relative = value.startswith("//")

        # Relative references are allowed.
        if not protocol_relative and not ANY_SCHEME_RE.match(value):
            continue

        candidate = "https:" + value if protocol_relative else value

        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
        except ValueError:
            # Malformed absolute URL: cannot establish an allowed host.
            return True

        if not hostname:
            return True

        # IMPORTANT: exact hostname comparison.
        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ------------------------------------------------------------
# Channel rules
# ------------------------------------------------------------

SCRIPT_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_RE = re.compile(
    r"\bon[A-Za-z0-9_-]*\s*=",
    re.IGNORECASE,
)

SQL_RE = re.compile(
    r"""
    '                       # single quote
    |
    "                       # double quote
    |
    ;
    |
    --
    |
    /\*
    |
    \bunion\b
    |
    \bor\s+1\s*=\s*1\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SHELL_RE = re.compile(
    r"""
    [;&|`<>]
    |
    \$\(
    |
    \$\{
    """,
    re.VERBOSE,
)


def check_original(channel: str, output: str) -> str:

    if channel == "html":
        if SCRIPT_RE.search(output):
            return "SCRIPT_TAG"

        if EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"

        if dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "markdown":
        if dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "url":
        if dangerous_scheme(channel, output):
            return "DANGEROUS_SCHEME"

        if external_exfil(channel, output):
            return "EXTERNAL_EXFIL"

        return "SAFE"

    if channel == "sql":
        return "SQL_METACHAR" if SQL_RE.search(output) else "SAFE"

    if channel == "shell":
        return "SHELL_METACHAR" if SHELL_RE.search(output) else "SAFE"

    return "INVALID_SCHEMA"


# ------------------------------------------------------------
# Endpoint
# ------------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # Do not let FastAPI turn malformed JSON into its own 422 schema.
    try:
        body = await request.json()
    except Exception:
        return result("INVALID_SCHEMA")

    # Rule 1
    if not isinstance(body, dict):
        return result("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in CHANNELS:
        return result("INVALID_SCHEMA")

    if not isinstance(output, str):
        return result("INVALID_SCHEMA")

    if len(output) > 20000:
        return result("INVALID_SCHEMA")

    # Rule 2
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_original(channel, decoded)

        if decoded_reason != "SAFE":
            return result("ENCODED_PAYLOAD")

    # Rule 3
    return result(check_original(channel, output))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
