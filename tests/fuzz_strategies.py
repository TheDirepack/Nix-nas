"""Shared Hypothesis strategies for structured NAS fuzz/property tests.

This module intentionally contains no RNG or mutation engine. Hypothesis owns
input generation, targeting, shrinking, and reproduction; tests only describe
valid or adversarial input shapes and assert invariants.
"""

from __future__ import annotations

from typing import Any

from hypothesis import strategies as st


def _identifier_fragment(*, min_size: int = 0, max_size: int) -> st.SearchStrategy[str]:
    return st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            blacklist_characters="/\\\x00\r\n\t ;|&$`",
        ),
        min_size=min_size,
        max_size=max_size,
    )


def identifier_candidates(*, max_size: int = 512) -> st.SearchStrategy[str]:
    """Generate ordinary identifiers plus structural grammar violations."""

    normal = st.text(
        alphabet=st.characters(blacklist_categories=("Cs",)),
        max_size=max_size,
    )
    fragment_size = max(1, min(max_size // 2, 128))
    fragment = _identifier_fragment(max_size=fragment_size)
    nonempty_fragment = _identifier_fragment(min_size=1, max_size=fragment_size)
    path_like = st.builds(
        lambda left, separator, right: f"{left}{separator}{right}",
        fragment,
        st.sampled_from(["/", "\\"]),
        fragment,
    )
    option_like = st.builds(
        lambda prefix, body: prefix + body,
        st.sampled_from(["-", "--"]),
        nonempty_fragment,
    )
    whitespace = st.builds(
        lambda left, separator, right: f"{left}{separator}{right}",
        fragment,
        st.sampled_from([" ", "\t", "\r", "\n"]),
        fragment,
    )
    shell_meta = st.builds(
        lambda left, metachar, right: f"{left}{metachar}{right}",
        fragment,
        st.sampled_from(list(";|&$`")),
        fragment,
    )
    traversal = st.builds(
        lambda separator, tail: f"..{separator}{tail}",
        st.sampled_from(["/", "\\"]),
        fragment,
    )
    control = st.builds(
        lambda left, character, right: f"{left}{character}{right}",
        fragment,
        st.sampled_from(["\x00", "\x1b", "\x7f", "\u202e", "\u2066", "\u2069"]),
        fragment,
    )
    return st.one_of(normal, path_like, option_like, whitespace, shell_meta, traversal, control)


def _render_path(parts: list[str], separator: str, prefix_kind: str, suffix_kind: str) -> str:
    prefix = {
        "relative": "",
        "absolute": separator,
        "dot": f".{separator}",
        "parent": f"..{separator}",
    }[prefix_kind]
    suffix = {
        "none": "",
        "separator": separator,
        "parent": f"{separator}..",
        "dot": f"{separator}.",
    }[suffix_kind]
    return prefix + separator.join(parts) + suffix


def path_candidates(*, max_components: int = 12) -> st.SearchStrategy[str]:
    ordinary_component = st.text(
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            blacklist_characters="/\\\x00\r\n",
        ),
        min_size=1,
        max_size=64,
    )
    special_component = st.one_of(
        st.just("."),
        st.just(".."),
        st.just("~"),
        st.builds(lambda prefix: prefix + ".", st.sampled_from(["-", ".", "%2e"])),
        st.builds(lambda marker, tail: marker + tail, st.sampled_from(["\u202e", "\u2066"]), ordinary_component),
    )
    component = st.one_of(ordinary_component, special_component)
    return st.builds(
        _render_path,
        st.lists(component, min_size=0, max_size=max_components),
        st.sampled_from(["/", "\\"]),
        st.sampled_from(["relative", "absolute", "dot", "parent"]),
        st.sampled_from(["none", "separator", "parent", "dot"]),
    )


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


def _render_secret_key(value: str, style: str, capitalize: bool) -> str:
    if style == "dash":
        value = value.replace("_", "-")
    elif style == "dot":
        value = value.replace("_", ".")
    elif style == "camel":
        head, *tail = value.split("_")
        value = head + "".join(part[:1].upper() + part[1:] for part in tail)
    elif style == "provider":
        value = f"provider_{value}"
    if capitalize and value:
        value = value[:1].upper() + value[1:]
    return value


def secret_key_names() -> st.SearchStrategy[str]:
    """Generate the naming conventions that should always trigger redaction."""

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
    return st.builds(
        _render_secret_key,
        base,
        st.sampled_from(["snake", "dash", "dot", "camel", "provider"]),
        st.booleans(),
    )
