"""Blog markdown → safe HTML rendering for the public threat-hunting blog.

Posts are authored as markdown by admins, then rendered server-side and
sanitised with bleach before being stored/served — the blog is public, so the
output must never carry author-supplied <script> or event handlers.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# Tags/attributes permitted in rendered post HTML. Generous enough for CTI
# reports (tables, code, images incl. embedded graph data URIs) but no script.
_ALLOWED_TAGS = [
    "p",
    "br",
    "hr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "strong",
    "em",
    "del",
    "blockquote",
    "code",
    "pre",
    "ul",
    "ol",
    "li",
    "a",
    "img",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "span",
    "div",
    # SVG subset — the case relationship graph is embedded as inline SVG so its
    # Font Awesome node icons render (same as the HTML report).
    "svg",
    "g",
    "defs",
    "marker",
    "line",
    "polyline",
    "polygon",
    "path",
    "rect",
    "circle",
    "ellipse",
    "text",
    "tspan",
    "title",
]
_SVG_ATTRS = [
    "viewbox",
    "viewBox",
    "xmlns",
    "width",
    "height",
    "x",
    "y",
    "x1",
    "y1",
    "x2",
    "y2",
    "cx",
    "cy",
    "r",
    "rx",
    "ry",
    "d",
    "points",
    "transform",
    "fill",
    "stroke",
    "stroke-width",
    "stroke-opacity",
    "stroke-dasharray",
    "fill-opacity",
    "opacity",
    "font-family",
    "font-size",
    "font-weight",
    "text-anchor",
    "dominant-baseline",
    "marker-end",
    "marker-start",
    "markerWidth",
    "markerHeight",
    "refX",
    "refY",
    "orient",
    "id",
    "class",
    "style",
]


def _link_attrs(tag: str, name: str, value: str) -> bool:
    """Attribute filter for <a>: links may only point to http(s)/mailto or be
    relative. data: stays allowed for <img> only (embedded graph images)."""
    if name in ("title", "rel", "target", "class"):
        return True
    if name == "href":
        v = value.strip().lower()
        return v.startswith(("http://", "https://", "mailto:", "/", "#")) or ":" not in v
    return False


_ALLOWED_ATTRS = {
    "a": _link_attrs,
    "img": ["src", "alt", "title"],
    "*": ["class"],
    "svg": _SVG_ATTRS,
    "g": _SVG_ATTRS,
    "defs": _SVG_ATTRS,
    "marker": _SVG_ATTRS,
    "line": _SVG_ATTRS,
    "polyline": _SVG_ATTRS,
    "polygon": _SVG_ATTRS,
    "path": _SVG_ATTRS,
    "rect": _SVG_ATTRS,
    "circle": _SVG_ATTRS,
    "ellipse": _SVG_ATTRS,
    "text": _SVG_ATTRS,
    "tspan": _SVG_ATTRS,
}
# Allow data: URIs so the embedded ECharts graph PNG survives sanitisation.
_ALLOWED_PROTOCOLS = ["http", "https", "mailto", "data"]


def render_md(md: str, *, hard_breaks: bool = True) -> str:
    """Render markdown to sanitised HTML. Falls back to escaped text if the
    optional deps are missing (keeps the app importable in minimal envs).

    `hard_breaks` turns single newlines into <br> (blog posts written in the
    editor); documents such as the changelog keep standard markdown wrapping."""
    try:
        import bleach
        import markdown as _md
    except ImportError:  # pragma: no cover - deps expected in prod
        from html import escape

        log.warning("markdown/bleach not installed — serving escaped text")
        return f"<pre>{escape(md or '')}</pre>"

    extensions = ["extra", "sane_lists", "fenced_code", "tables"]
    if hard_breaks:
        extensions.append("nl2br")
    html = _md.markdown(md or "", extensions=extensions)
    cleaned = bleach.clean(
        html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
    )
    return cleaned
