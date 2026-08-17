import re
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-ii3v6se.example",
    "app-teee7zh.example",
}

CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


# ============================================================
# RESPONSE
# ============================================================

def respond(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "safe": reason == "SAFE",
            "reason": reason,
        },
    )


# ============================================================
# ONE-PASS DECODING
#
# percent escapes
#       ↓
# HTML entities
#       ↓
# \uXXXX
# ============================================================

PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")

ENTITY_RE = re.compile(
    r"&(?:lt|gt|quot|apos|amp);"
    r"|&#[0-9]+;"
    r"|&#x[0-9A-Fa-f]+;",
    re.IGNORECASE,
)

UNICODE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")


def decode_percent(s: str) -> str:
    def replace(m):
        return chr(int(m.group(1), 16))

    return PERCENT_RE.sub(replace, s)


def decode_html_entities(s: str) -> str:
    def replace(m):
        token = m.group(0)
        lower = token.lower()

        if lower == "&lt;":
            return "<"
        if lower == "&gt;":
            return ">"
        if lower == "&quot;":
            return '"'
        if lower == "&apos;":
            return "'"
        if lower == "&amp;":
            return "&"

        body = token[2:-1]

        try:
            if body.lower().startswith("#x"):
                return chr(int(body[2:], 16))
            return chr(int(body[1:], 10))
        except Exception:
            return token

    return ENTITY_RE.sub(replace, s)


def decode_unicode(s: str) -> str:
    def replace(m):
        return chr(int(m.group(1), 16))

    return UNICODE_RE.sub(replace, s)


def decode_once(s: str) -> str:
    s = decode_percent(s)
    s = decode_html_entities(s)
    s = decode_unicode(s)
    return s


# ============================================================
# URL EXTRACTION
# ============================================================

HTML_ATTRIBUTE_RE = re.compile(
    r"""
    \b(?:src|href)
    \s*=
    \s*
    (?:
        "([^"]*)"
        |
        '([^']*)'
    )
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)


def extract_html_urls(s: str):
    result = []

    for match in HTML_ATTRIBUTE_RE.finditer(s):
        value = match.group(1)

        if value is None:
            value = match.group(2)

        result.append(value)

    return result


def extract_markdown_urls(s: str):
    result = []

    pos = 0

    while True:
        start = s.find("](", pos)

        if start == -1:
            break

        i = start + 2

        # Skip whitespace after ](
        while i < len(s) and s[i].isspace():
            i += 1

        if i >= len(s):
            break

        # <url> form
        if s[i] == "<":
            end = s.find(">", i + 1)

            if end == -1:
                pos = i + 1
                continue

            result.append(s[i + 1:end])

            close = s.find(")", end + 1)

            if close == -1:
                pos = end + 1
            else:
                pos = close + 1

            continue

        # Normal markdown target.
        # Find closing ')' while respecting nested parentheses.
        target_start = i
        depth = 0
        quote = None

        while i < len(s):
            c = s[i]

            if quote:
                if c == quote:
                    quote = None

            elif c in ("'", '"'):
                quote = c

            elif c == "(":
                depth += 1

            elif c == ")":
                if depth == 0:
                    break
                depth -= 1

            i += 1

        if i >= len(s):
            break

        target = s[target_start:i].strip()

        # Optional markdown title:
        # [x](URL "title")
        if target:
            if target.startswith("http://") or target.startswith("https://"):
                pass
            elif target.startswith("//"):
                pass
            else:
                # For arbitrary schemes and relative references, take
                # the first whitespace-delimited target.
                target = target.split(None, 1)[0]

            if target:
                result.append(target)

        pos = i + 1

    return result


def extract_urls(channel: str, output: str):
    if channel == "html":
        return extract_html_urls(output)

    if channel == "markdown":
        return extract_markdown_urls(output)

    if channel == "url":
        return [output.strip()]

    return []


# ============================================================
# SCHEMES
# ============================================================

DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)

SCHEME_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9+.-]*)\s*:"
)


def has_dangerous_scheme(channel: str, output: str) -> bool:

    # Explicit textual dangerous schemes.
    if DANGEROUS_SCHEME_RE.search(output):
        return True

    # Extracted URLs.
    for raw in extract_urls(channel, output):

        value = raw.strip()

        if not value:
            continue

        # Protocol-relative URL is HTTPS.
        if value.startswith("//"):
            candidate = "https:" + value
        else:
            candidate = value

        match = SCHEME_RE.match(candidate)

        if match:
            scheme = match.group(1).lower()

            if scheme not in {"http", "https"}:
                return True

    return False


# ============================================================
# EXTERNAL EXFILTRATION
# ============================================================

def has_external_exfil(channel: str, output: str) -> bool:

    for raw in extract_urls(channel, output):

        value = raw.strip()

        if not value:
            continue

        protocol_relative = value.startswith("//")

        # Relative references are allowed.
        if not protocol_relative and not SCHEME_RE.match(value):
            continue

        candidate = (
            "https:" + value
            if protocol_relative
            else value
        )

        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
        except Exception:
            return True

        if not hostname:
            return True

        # Exact hostname comparison.
        if hostname.lower() not in ALLOWED_HOSTS:
            return True

    return False


# ============================================================
# HTML
# ============================================================

SCRIPT_TAG_RE = re.compile(
    r"<\s*(?:script|iframe|object|embed)\b",
    re.IGNORECASE,
)

EVENT_HANDLER_RE = re.compile(
    r"\bon[A-Za-z0-9_-]*\s*=",
    re.IGNORECASE,
)


# ============================================================
# SQL
# ============================================================

SQL_META_RE = re.compile(
    r"""
    '
    |
    "
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


# ============================================================
# SHELL
# ============================================================

SHELL_META_RE = re.compile(
    r"""
    [;&|`<>]
    |
    \$\(
    |
    \$\{
    """,
    re.VERBOSE,
)


# ============================================================
# CHANNEL EVALUATION
# ============================================================

def evaluate(channel: str, output: str) -> str:

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
        if SQL_META_RE.search(output):
            return "SQL_METACHAR"

        return "SAFE"

    if channel == "shell":
        if SHELL_META_RE.search(output):
            return "SHELL_METACHAR"

        return "SAFE"

    return "INVALID_SCHEMA"


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/sanitize-output")
@app.post("/sanitize-output/")
async def sanitize_output(request: Request):

    # --------------------------------------------------------
    # Rule 1: INVALID_SCHEMA
    # --------------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return respond("INVALID_SCHEMA")

    if not isinstance(body, dict):
        return respond("INVALID_SCHEMA")

    channel = body.get("channel")
    output = body.get("output")

    if channel not in CHANNELS:
        return respond("INVALID_SCHEMA")

    if not isinstance(output, str):
        return respond("INVALID_SCHEMA")

    if len(output) > 20000:
        return respond("INVALID_SCHEMA")

    # --------------------------------------------------------
    # Rule 2: ENCODED_PAYLOAD
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = evaluate(
            channel,
            decoded,
        )

        if decoded_reason != "SAFE":
            return respond("ENCODED_PAYLOAD")

    # --------------------------------------------------------
    # Rule 3: ORIGINAL OUTPUT
    # --------------------------------------------------------

    reason = evaluate(
        channel,
        output,
    )

    return respond(reason)


# ============================================================
# BASIC AVAILABILITY
# ============================================================

@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
