"""Shared Hypothesis strategies for structured NAS fuzz/property tests.

This module intentionally contains no RNG or mutation engine. Hypothesis owns
input generation, targeting, shrinking, and reproduction; tests only describe
valid or adversarial input shapes and assert invariants.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st

MAX_TEXT = 8192

CONTROL_CHARS = "\x00\r\n\t\x1b\x7f"
PATH_SEPARATORS = "/\\"
SHELL_METACHARS = ";|&$`<>(){}[]'\""


def bounded_text(*, max_size: int = MAX_TEXT) -> st.SearchStrategy[str]:
    return st.text(max_size=max_size)


def identifier_candidates(*, max_size: int = 512) -> st.SearchStrategy[str]:
    """Generate ordinary and grammar-hostile identifier candidates."""

    normal = st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            blacklist_characters="\x00\r\n",
        ),
        max_size=max_size,
    )
    hostile = st.sampled_from(
        [
            "..",
            "../x",
            "..\\x",
            "/absolute",
            "a/b",
            "a\\b",
            "--option",
            "-x",
            "a b",
            "a\tb",
            "a\nb",
            "a\x00b",
            "a;b",
            "a|b",
            "a&b",
            "a$b",
            "a`b",
            "\u202eadmin",
        ]
    )
    return st.one_of(normal, hostile)


def path_candidates(*, max_components: int = 12) -> st.SearchStrategy[str]:
    component = st.one_of(
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cs",),
                blacklist_characters="/\\\x00\r\n",
            ),
            min_size=1,
            max_size=64,
        ),
        st.sampled_from([".", "..", "~", "-", "--", "%2e%2e", "\u202e"]),
    )

    @st.composite
    def build(draw) -> str:
        parts = draw(st.lists(component, min_size=0, max_size=max_components))
        separator = draw(st.sampled_from(["/", "\\"]))
        prefix = draw(st.sampled_from(["", separator, f".{separator}", f"..{separator}"]))
        suffix = draw(st.sampled_from(["", separator, f"{separator}..", f"{separator}."]))
        return prefix + separator.join(parts) + suffix

    return build()


def json_values(*, max_leaves: int = 80) -> st.SearchStrategy[Any]:
    scalar = st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=1024),
    )
    return st.recursive(
        scalar,
        lambda children: st.one_of(
            st.lists(children, max_size=24),
            st.dictionaries(st.text(max_size=128), children, max_size=24),
        ),
        max_leaves=max_leaves,
    )


def secret_key_names() -> st.SearchStrategy[str]:
    base = st.sampled_from(
        [
            "password",
            "passwd",
            "token",
            "secret",
            "api_key",
            "access_key",
            "private_key",
            "client_secret",
            "access_token",
            "refresh_token",
            "session_token",
            "cookie",
            "authorization",
        ]
    )

    @st.composite
    def render(draw) -> str:
        value = draw(base)
        style = draw(st.sampled_from(["snake", "dash", "dot", "camel", "provider"]))
        if style == "dash":
            value = value.replace("_", "-")
        elif style == "dot":
            value = value.replace("_", ".")
        elif style == "camel":
            head, *tail = value.split("_")
            value = head + "".join(part[:1].upper() + part[1:] for part in tail)
        elif style == "provider":
            value = f"provider_{value}"
        if draw(st.booleans()) and value:
            value = value[:1].upper() + value[1:]
        return value

    return render()
