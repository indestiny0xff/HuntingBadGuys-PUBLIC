"""
Minimal AST-based query language for filtering investigation results.

Grammar (EBNF):
    query     = expr EOF
    expr      = and_expr ("OR" and_expr)*
    and_expr  = not_expr ("AND" not_expr)*
    not_expr  = "NOT" not_expr | atom
    atom      = "(" expr ")" | predicate
    predicate = field op value
              | field "exists"
              | field "not" "exists"
    field     = IDENT ("." IDENT)*        (hyphens allowed inside IDENT)
    op        = "==" | "!=" | "contains" | "startswith" | "endswith" | "~=" | "in"
    value     = STRING | NUMBER

Examples:
    dns.A == "1.2.3.4"
    final_headers.server contains "nginx" AND final_status == 200
    NOT whois.registrar exists
    certs.san ~= "^login\\."
    files.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    bgp.asn.asn == "AS12345" OR bgp.asn.asn == "AS67890"
    dns.MX.exchange contains "google"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

# ── Lexer ─────────────────────────────────────────────────────────────────────


class TT(Enum):
    IDENT = auto()
    DOT = auto()
    OP = auto()
    STRING = auto()
    NUMBER = auto()
    LPAREN = auto()
    RPAREN = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    EXISTS = auto()
    EOF = auto()


@dataclass(frozen=True)
class Token:
    type: TT
    value: str | float | int | None


_KEYWORDS: dict[str, TT] = {
    "AND": TT.AND,
    "and": TT.AND,
    "OR": TT.OR,
    "or": TT.OR,
    "NOT": TT.NOT,
    "not": TT.NOT,
    "exists": TT.EXISTS,
}
_OPERATORS: frozenset[str] = frozenset(
    {"==", "!=", "~=", "contains", "startswith", "endswith", "in"}
)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)

    while i < n:
        ch = text[i]

        if ch.isspace():
            i += 1

        elif ch == "(":
            tokens.append(Token(TT.LPAREN, "("))
            i += 1

        elif ch == ")":
            tokens.append(Token(TT.RPAREN, ")"))
            i += 1

        elif ch in ('"', "'"):
            j = i + 1
            buf: list[str] = []
            while j < n and text[j] != ch:
                if text[j] == "\\" and j + 1 < n:
                    j += 1
                    # Preserve unrecognised escapes (e.g. \d, \w for regex patterns)
                    buf.append(
                        {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "'": "'"}.get(
                            text[j], "\\" + text[j]
                        )
                    )
                else:
                    buf.append(text[j])
                j += 1
            tokens.append(Token(TT.STRING, "".join(buf)))
            i = j + 1

        elif text[i : i + 2] in ("==", "!=", "~="):
            tokens.append(Token(TT.OP, text[i : i + 2]))
            i += 2

        elif ch.isdigit() or (ch == "-" and i + 1 < n and text[i + 1].isdigit()):
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            raw = text[i:j]
            tokens.append(Token(TT.NUMBER, float(raw) if "." in raw else int(raw)))
            i = j

        elif ch.isalpha() or ch == "_":
            # Allow hyphens mid-word (e.g. x-powered-by, content-type)
            j = i + 1
            while j < n:
                c = text[j]
                if c.isalnum() or c == "_" or (c == "-" and j + 1 < n and text[j + 1].isalnum()):
                    j += 1
                else:
                    break
            word = text[i:j]
            if word in _KEYWORDS:
                tokens.append(Token(_KEYWORDS[word], word))
            elif word in _OPERATORS:
                tokens.append(Token(TT.OP, word))
            else:
                tokens.append(Token(TT.IDENT, word))
            i = j

        elif ch == ".":
            tokens.append(Token(TT.DOT, "."))
            i += 1

        else:
            i += 1  # skip unknown character

    tokens.append(Token(TT.EOF, None))
    return tokens


# ── AST nodes ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AndNode:
    left: Any
    right: Any


@dataclass(frozen=True)
class OrNode:
    left: Any
    right: Any


@dataclass(frozen=True)
class NotNode:
    child: Any


@dataclass(frozen=True)
class CompareNode:
    field: str
    op: str
    value: str | int | float


@dataclass(frozen=True)
class ExistsNode:
    field: str
    negated: bool = False


ASTNode = AndNode | OrNode | NotNode | CompareNode | ExistsNode


# ── Parser ────────────────────────────────────────────────────────────────────


class QueryParseError(ValueError):
    pass


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._t = tokens
        self._pos = 0

    @property
    def _cur(self) -> Token:
        return self._t[self._pos]

    def _eat(self, tt: TT) -> Token:
        if self._cur.type != tt:
            raise QueryParseError(
                f"expected {tt.name}, got {self._cur.type.name!r} ({self._cur.value!r})"
            )
        tok = self._cur
        self._pos += 1
        return tok

    def parse(self) -> ASTNode:
        node = self._expr()
        self._eat(TT.EOF)
        return node

    def _expr(self) -> ASTNode:
        node = self._and_expr()
        while self._cur.type == TT.OR:
            self._pos += 1
            node = OrNode(node, self._and_expr())
        return node

    def _and_expr(self) -> ASTNode:
        node = self._not_expr()
        while self._cur.type == TT.AND:
            self._pos += 1
            node = AndNode(node, self._not_expr())
        return node

    def _not_expr(self) -> ASTNode:
        if self._cur.type == TT.NOT:
            self._pos += 1
            return NotNode(self._not_expr())
        return self._atom()

    def _atom(self) -> ASTNode:
        if self._cur.type == TT.LPAREN:
            self._pos += 1
            node = self._expr()
            self._eat(TT.RPAREN)
            return node
        return self._predicate()

    def _field(self) -> str:
        parts: list[str] = [str(self._eat(TT.IDENT).value)]
        while self._cur.type == TT.DOT:
            self._pos += 1
            parts.append(str(self._eat(TT.IDENT).value))
        return ".".join(parts)

    def _predicate(self) -> ASTNode:
        field = self._field()

        if self._cur.type == TT.EXISTS:
            self._pos += 1
            return ExistsNode(field, negated=False)

        if self._cur.type == TT.NOT:
            self._pos += 1
            self._eat(TT.EXISTS)
            return ExistsNode(field, negated=True)

        if self._cur.type != TT.OP:
            raise QueryParseError(f"expected operator after field {field!r}, got {self._cur}")
        op = str(self._cur.value)
        self._pos += 1

        if self._cur.type not in (TT.STRING, TT.NUMBER):
            raise QueryParseError(f"expected value after operator, got {self._cur}")
        value = self._cur.value
        self._pos += 1
        return CompareNode(field, op, value)  # type: ignore[arg-type]


def parse(query: str) -> ASTNode:
    return _Parser(tokenize(query)).parse()


def _regex_values(node: ASTNode) -> list[str]:
    match node:
        case AndNode(left, right) | OrNode(left, right):
            return _regex_values(left) + _regex_values(right)
        case NotNode(child):
            return _regex_values(child)
        case CompareNode(_, "~=", value):
            return [str(value)]
    return []


def validate(query: str) -> ASTNode:
    """Parse a user-supplied query and reject pathological regex patterns.

    Raises QueryParseError (a ValueError) with a readable message.
    """
    from ..security import validate_user_regex

    ast = parse(query)
    for pattern in _regex_values(ast):
        try:
            validate_user_regex(pattern)
        except ValueError as exc:
            raise QueryParseError(str(exc)) from exc
    return ast


# ── Projection (flatten to dot-notation dict) ─────────────────────────────────


def _merge(out: dict[str, Any], key: str, value: Any) -> None:
    if key not in out:
        out[key] = value
        return
    existing = out[key]
    # Coerce both sides to list and concatenate
    lhs = existing if isinstance(existing, list) else [existing]
    rhs = value if isinstance(value, list) else [value]
    out[key] = lhs + rhs


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a dict/Pydantic model to dot-notation keys.

    List[dict] fields are kept as-is *and* their sub-keys are aggregated
    so queries like ``dns.MX.exchange contains "..."`` work across all items.
    """
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump()

    out: dict[str, Any] = {}

    if isinstance(obj, dict):
        if prefix:
            # Preserve the parent key so `geo exists` / `bgp exists` work.
            out[prefix] = obj
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            for sk, sv in flatten(v, key).items():
                _merge(out, sk, sv)

    elif isinstance(obj, list):
        out[prefix] = obj  # keep original list at the parent key
        for item in obj:
            if isinstance(item, dict):
                for k, v in item.items():
                    key = f"{prefix}.{k}"
                    for sk, sv in flatten(v, key).items():
                        _merge(out, sk, sv)
            # Scalar list items (str, int…) already captured in out[prefix]

    else:
        out[prefix] = obj

    return out


# ── Evaluator ─────────────────────────────────────────────────────────────────


def _match_single(actual: Any, op: str, expected: Any) -> bool:
    """Match a single (possibly list) value against expected with the given op."""
    if isinstance(actual, list):
        return any(_match_single(item, op, expected) for item in actual)
    if actual is None:
        return False
    a = str(actual).lower()
    e = str(expected).lower()
    match op:
        case "==":
            return a == e
        case "!=":
            return a != e
        case "contains":
            return e in a
        case "startswith":
            return a.startswith(e)
        case "endswith":
            return a.endswith(e)
        case "~=":
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        case "in":
            return a in e
        case _:
            return False


def _eval(node: ASTNode, flat: dict[str, Any]) -> bool:
    match node:
        case AndNode(left, right):
            return _eval(left, flat) and _eval(right, flat)
        case OrNode(left, right):
            return _eval(left, flat) or _eval(right, flat)
        case NotNode(child):
            return not _eval(child, flat)
        case ExistsNode(field, negated):
            val = flat.get(field)
            exists = val is not None and val != [] and val != "" and val != {}
            return (not exists) if negated else exists
        case CompareNode(field, op, value):
            val = flat.get(field)
            if isinstance(val, list):
                return any(_match_single(v, op, value) for v in val)
            return _match_single(val, op, value)
    return False


def evaluate(query: str, result: Any) -> bool:
    """Return True if *result* matches *query*."""
    ast = parse(query)
    flat = flatten(result)
    return _eval(ast, flat)


def filter_results(query: str, results: list[Any]) -> list[Any]:
    """Filter a list of results, skipping items that cause evaluation errors."""
    ast = parse(query)
    out: list[Any] = []
    for r in results:
        flat = flatten(r)
        try:
            if _eval(ast, flat):
                out.append(r)
        except Exception:
            pass
    return out
