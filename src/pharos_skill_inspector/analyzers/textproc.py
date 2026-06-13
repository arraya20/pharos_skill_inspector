"""Lightweight source preprocessing shared by the C-like analyzers.

We don't ship a full JS/Solidity parser (zero-dependency goal), but naive regex
over raw source produces false positives by matching inside comments and string
literals. ``mask_code`` returns a string of identical length where the *contents*
of comments and string/template literals are replaced with spaces. Newlines and
character offsets are preserved, so line numbers computed on the masked text map
directly back to the original source.

This gives "token-aware" scanning: patterns only match real code, while we still
report evidence from the original line.
"""

from __future__ import annotations


def mask_code(text: str, *, template_literals: bool = True) -> str:
    """Blank out comment and string-literal contents in C-like source.

    Args:
        text: raw source.
        template_literals: treat backtick `` ` `` strings as literals (JS/TS).
            Set False for Solidity, which has no template literals.
    """
    out = list(text)
    i = 0
    n = len(text)
    state = "code"          # code | line_comment | block_comment | string
    quote = ""

    def blank(idx: int) -> None:
        if out[idx] != "\n":
            out[idx] = " "

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                blank(i); blank(i + 1); i += 2; continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                blank(i); blank(i + 1); i += 2; continue
            if ch in ("'", '"') or (template_literals and ch == "`"):
                state = "string"; quote = ch
                i += 1; continue  # keep the opening quote visible
            i += 1; continue

        if state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                blank(i)
            i += 1; continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                blank(i); blank(i + 1); state = "code"; i += 2; continue
            blank(i); i += 1; continue

        if state == "string":
            if ch == "\\":  # escape: blank the pair
                blank(i)
                if i + 1 < n:
                    blank(i + 1)
                i += 2; continue
            if ch == quote:
                state = "code"; i += 1; continue  # keep closing quote
            blank(i); i += 1; continue

    return "".join(out)
