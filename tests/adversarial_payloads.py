"""Shared deterministic hostile-input corpus for security and fuzz tests."""

SQL_PAYLOADS = (
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    '" OR 1=1 --',
    "admin'/**/OR/**/'1'='1",
    "' UNION SELECT NULL,NULL --",
    "1; SELECT pg_sleep(10); --",
    "') OR ('1'='1",
)

SHELL_PAYLOADS = (
    "; id",
    "$(id)",
    "`id`",
    "| cat /etc/shadow",
    "&& touch /tmp/nas-injection",
    "\n/bin/sh -c id",
    "${IFS}id",
    "--help;touch /tmp/nas-injection",
)

XSS_PAYLOADS = (
    "<script>globalThis.__nas_xss=1</script>",
    '<img src=x onerror="globalThis.__nas_xss=1">',
    "<svg/onload=globalThis.__nas_xss=1>",
    "javascript:globalThis.__nas_xss=1",
    "</textarea><script>globalThis.__nas_xss=1</script>",
    '<iframe srcdoc="<script>globalThis.__nas_xss=1</script>"></iframe>',
    '<a href="data:text/html,<script>globalThis.__nas_xss=1</script>">x</a>',
)

PATH_PAYLOADS = (
    "../etc/shadow",
    "../../../../root/.ssh/authorized_keys",
    "/etc/passwd",
    "..\\..\\Windows\\System32",
    "%2e%2e/%2e%2e/etc/passwd",
    "./.././../etc/passwd",
    "..%2f..%2fetc%2fshadow",
    "..\x00/etc/passwd",
)

CONTROL_PAYLOADS = (
    "nas_admin\r\nX-Injected: yes",
    "nas_admin\nX-Injected: yes",
    "nas_admin\x00nas_disabled",
    "nas_admin\x1fnas_users",
    "nas_admin\x7fnas_users",
    "nas_admin\t,nas_users",
)

TEMPLATE_PAYLOADS = (
    "{{7*7}}",
    "${7*7}",
    "<%= 7 * 7 %>",
    "#{7*7}",
)

URL_PAYLOADS = (
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1@evil.invalid/",
    "http://localhost.evil.invalid/",
    "http://[::1]@evil.invalid/",
    "file:///etc/passwd",
    "https://127.0.0.1/",
)

UNICODE_PAYLOADS = (
    "\u202eadmin",
    "nas_admin\u2066evil\u2069",
    "ＡＤＭＩＮ",
    "admin\u0301",
    "🧪" * 512,
)

ALL_TEXT_PAYLOADS = (
    SQL_PAYLOADS
    + SHELL_PAYLOADS
    + XSS_PAYLOADS
    + PATH_PAYLOADS
    + CONTROL_PAYLOADS
    + TEMPLATE_PAYLOADS
    + URL_PAYLOADS
    + UNICODE_PAYLOADS
)
