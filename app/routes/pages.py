"""HTML pages, static assets and crawler files (robots, sitemap).

Pages are plain HTML files in ``static/``. They are served through
``render_page`` which fills the branding placeholders (``{{APP_NAME}}``,
``{{BRAND_A}}``, ``{{BRAND_B}}``) and links ``/branding.css`` so the operator's
``HUNTER_APP_NAME`` and ``HUNTER_THEME`` apply everywhere.
"""

from __future__ import annotations

import html
import logging
import pathlib
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response

from .. import db as _db_module
from ..config import settings

log = logging.getLogger(__name__)
router = APIRouter()

STATIC_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "static"
_page_cache: dict[str, tuple[float, str]] = {}

# Accent palettes. "purple" matches the original design; "black" is a
# monochrome variant with deeper surfaces.
_THEMES: dict[str, dict[str, str]] = {
    "purple": {"accent": "#7c3aed", "accent2": "#6d28d9", "rgb": "124,58,237"},
    "red": {"accent": "#ef4444", "accent2": "#dc2626", "rgb": "239,68,68"},
    "green": {"accent": "#22c55e", "accent2": "#16a34a", "rgb": "34,197,94"},
    "blue": {"accent": "#3b82f6", "accent2": "#2563eb", "rgb": "59,130,246"},
    "black": {"accent": "#e2e8f0", "accent2": "#94a3b8", "rgb": "226,232,240"},
}
# Per-browser accent override: the selector on every page stores the choice in
# localStorage and swaps the stylesheet; the server default applies otherwise.
_THEME_SCRIPT = (
    "(function(){var T=" + str(list(_THEMES)).replace("'", '"') + ";"
    "function cur(){try{var t=localStorage.getItem('hbg-theme');if(T.indexOf(t)>=0)return t}catch(e){}"
    "var m=document.querySelector('meta[name=app-theme]');return m?m.content:'purple'}"
    "function apply(t){if(T.indexOf(t)<0)return;try{localStorage.setItem('hbg-theme',t)}catch(e){}"
    "var l=document.getElementById('branding-css');if(l)l.href='/branding.css?theme='+t;mark(t);"
    "document.querySelectorAll('.theme-menu.open').forEach(function(x){x.classList.remove('open')})}"
    "window.hbgApplyTheme=apply;window.hbgCurrentTheme=cur;"
    "var t=cur();var l=document.getElementById('branding-css');if(l&&t)l.href='/branding.css?theme='+t;"
    "function mark(t){document.querySelectorAll('.theme-list button').forEach(function(b){"
    "b.classList.toggle('active',b.getAttribute('data-theme')===t)})}"
    "window.hbgToggleThemeMenu=function(ev){ev.stopPropagation();var m=ev.currentTarget.closest('.theme-menu');"
    "var open=!m.classList.contains('open');document.querySelectorAll('.theme-menu.open').forEach(function(x){x.classList.remove('open')});"
    "m.classList.toggle('open',open);ev.currentTarget.setAttribute('aria-expanded',open)};"
    "document.addEventListener('click',function(){document.querySelectorAll('.theme-menu.open').forEach(function(x){x.classList.remove('open')})});"
    "function mode(){try{return localStorage.getItem('theme')||'dark'}catch(e){return 'dark'}}"
    "function setMode(m){var h=document.documentElement;if(m==='light')h.setAttribute('data-theme','light');"
    "else h.removeAttribute('data-theme');try{localStorage.setItem('theme',m)}catch(e){}"
    "document.querySelectorAll('.mode-btn .mode-icon').forEach(function(i){i.textContent=m==='light'?'\u263d':'\u2600'})}"
    "window.hbgToggleMode=function(){setMode(mode()==='light'?'dark':'light')};"
    "setMode(mode());"
    "document.addEventListener('DOMContentLoaded',function(){mark(cur());setMode(mode())})})();"
)

_THEME_CSS = (
    ".theme-menu{position:relative;display:inline-flex}"
    ".theme-menu .theme-btn{display:inline-flex;align-items:center;gap:.45rem;cursor:pointer}"
    ".theme-dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--accent);display:inline-block;flex-shrink:0}"
    ".theme-list{position:absolute;right:0;top:calc(100% + .4rem);min-width:150px;"
    "background:var(--surf,#080c18);border:1px solid var(--border2,#1e2f4a);border-radius:8px;padding:.3rem;"
    "display:none;flex-direction:column;gap:.1rem;z-index:1000;box-shadow:0 12px 30px rgba(0,0,0,.45)}"
    ".theme-menu.open .theme-list{display:flex}"
    ".theme-list button{display:flex;align-items:center;gap:.5rem;width:100%;background:none;border:0;"
    "color:var(--text,#e4ecf8);font:inherit;font-size:.75rem;padding:.42rem .6rem;border-radius:5px;cursor:pointer;text-align:left}"
    ".theme-list button:hover{background:var(--surf2,#0d1224)}"
    ".theme-list button.active{color:var(--accent);font-weight:600}"
    # Light mode: the shared palette every page's variables map onto. index.html
    # ships its own, more detailed light overrides on top of this.
    "[data-theme=light]{--bg:#f5f0e8;--surf:#fdf9f3;--surf-s:#fdf9f3;--surf2:#ede8de;--surf3:#e3ddd2;"
    "--border:#d3ccc0;--border2:#bfb8ac;--text:#1c1814;--muted:#7d7062;--dim:#4f4338;"
    "--shadow:0 4px 24px rgba(0,0,0,.12);color-scheme:light}"
    "[data-theme=light] body{background:var(--bg);color:var(--text)}"
    "[data-theme=light] .theme-list{box-shadow:0 12px 30px rgba(0,0,0,.15)}"
    ".mode-btn{cursor:pointer;display:inline-flex;align-items:center;justify-content:center;min-width:2.1rem}"
)

_BLACK_SURFACES = (
    "--bg:#000000;--surf:#050505;--surf-s:#050505;--surf2:#0a0a0a;--surf3:#111111;"
    "--border:#1f1f1f;--border2:#2a2a2a;"
)


def brand_parts() -> tuple[str, str]:
    """Split the app name into the two wordmark halves (e.g. HUNTING / BADGUYS)."""
    words = settings.app_name.split()
    if not words:
        return "APP", ""
    return words[0].upper(), "".join(words[1:]).upper()


def render_page(filename: str, extra_head: str = "", **placeholders: str) -> str:
    """Return a static page with branding placeholders filled in.

    Files are cached by modification time so edits show up without a restart.
    """
    path = STATIC_DIR / filename
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Page not found")
    cached = _page_cache.get(filename)
    if cached and cached[0] == mtime:
        page = cached[1]
    else:
        page = path.read_text(encoding="utf-8")
        _page_cache[filename] = (mtime, page)

    brand_a, brand_b = brand_parts()
    values = {
        "APP_NAME": html.escape(settings.app_name),
        "BRAND_A": html.escape(brand_a),
        "BRAND_B": html.escape(brand_b),
        "PUBLIC_URL": html.escape(settings.public_url),
        "YEAR": time.strftime("%Y"),
        **placeholders,
    }
    for key, value in values.items():
        page = page.replace("{{" + key + "}}", value)
    head = (
        f'<meta name="app-name" content="{values["APP_NAME"]}"/>'
        f'<meta name="app-theme" content="{settings.theme}"/>'
        f'<link id="branding-css" rel="stylesheet" href="/branding.css"/>'
        f"<style>{_THEME_CSS}</style><script>{_THEME_SCRIPT}</script>{extra_head}\n</head>"
    )
    return page.replace("</head>", head, 1)


def page_response(filename: str, **kwargs) -> HTMLResponse:
    return HTMLResponse(render_page(filename, **kwargs))


# ── Health and branding ───────────────────────────────────────────────────────


@router.get("/health", include_in_schema=False)
async def health() -> dict:
    from .. import __version__

    return {"status": "ok", "version": __version__}


@router.get("/branding.css", include_in_schema=False)
async def branding_css(theme: str | None = None) -> Response:
    """Accent palette CSS. `?theme=` lets a browser override the server default."""
    name = theme if theme in _THEMES else settings.theme
    palette = _THEMES[name]
    css = (
        ":root,:root[data-theme]{"
        f"--accent:{palette['accent']};--accent2:{palette['accent2']};"
        f"--accent-rgb:{palette['rgb']};"
        f"--accent-soft:rgba({palette['rgb']},.12);--accent-line:rgba({palette['rgb']},.45);"
        f"--accent-g:linear-gradient(135deg,{palette['accent']},{palette['accent2']});"
        + "}\n"
        # The black theme darkens the surfaces too, but only in dark mode so the
        # light palette stays readable when both are combined.
        + (":root:not([data-theme=light]){" + _BLACK_SURFACES + "}\n" if name == "black" else "")
    )
    return Response(css, media_type="text/css", headers={"Cache-Control": "no-cache"})


# ── Pages ─────────────────────────────────────────────────────────────────────


@router.get("/", include_in_schema=False)
async def index():
    return page_response("public.html")


@router.get("/public", include_in_schema=False)
async def public_page():
    return page_response("public.html")


@router.get("/app", include_in_schema=False)
async def app_page():
    return page_response("index.html")


@router.get("/login", include_in_schema=False)
async def login_page():
    return page_response("login.html")


@router.get("/intel", include_in_schema=False)
async def intel_page():
    # The page JS gates on /auth/me and redirects to /login when unauthenticated.
    return page_response("intel.html")


@router.get("/blog", include_in_schema=False)
async def blog_page():
    return page_response("blog.html")


@router.get("/blog/{slug}", include_in_schema=False)
async def blog_post_page(slug: str):
    """Public post page with server-injected SEO meta (title, description, og)."""
    post = await _db_module.get_db().get_post_by_slug(slug)
    app_name = html.escape(settings.app_name)
    if post and post.get("is_published"):
        title = html.escape(post.get("title") or "Threat Hunting")
        desc = html.escape((post.get("summary") or "")[:300])
        url = f"{settings.public_url}/blog/{html.escape(slug)}"
        meta = (
            f"<title>{title} - {app_name}</title>"
            f'<meta name="description" content="{desc}"/>'
            f'<meta property="og:title" content="{title}"/>'
            f'<meta property="og:description" content="{desc}"/>'
            f'<meta property="og:type" content="article"/>'
            f'<meta property="og:url" content="{url}"/>'
            f'<link rel="canonical" href="{url}"/>'
        )
    else:
        meta = f'<title>Post not found - {app_name}</title><meta name="robots" content="noindex"/>'
    return page_response("blog_post.html", SEO_META=meta)


@router.get("/features", include_in_schema=False)
async def features_page():
    return page_response("features.html")


# ── Static assets ─────────────────────────────────────────────────────────────


@router.get("/query_domain.png", include_in_schema=False)
async def query_domain_png():
    return FileResponse(STATIC_DIR / "query_domain.png", media_type="image/png")


@router.get("/query_ip.png", include_in_schema=False)
async def query_ip_png():
    return FileResponse(STATIC_DIR / "query_ip.png", media_type="image/png")


@router.get("/favicon.svg", include_in_schema=False)
async def favicon_svg():
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


@router.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


# ── Crawlers ──────────────────────────────────────────────────────────────────


@router.get("/robots.txt", include_in_schema=False)
async def robots_txt():
    content = (
        "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /admin/\nDisallow: /app\n\n"
        f"Sitemap: {settings.public_url}/sitemap.xml\n"
    )
    return PlainTextResponse(content, media_type="text/plain")


@router.get("/sitemap.xml", include_in_schema=False)
async def sitemap_xml():
    base = settings.public_url
    urls = [(f"{base}/", "monthly", "1.0"), (f"{base}/blog", "daily", "0.9")]
    try:
        for p in await _db_module.get_db().list_published_posts(limit=1000):
            urls.append((f"{base}/blog/{html.escape(p['slug'])}", "weekly", "0.7"))
    except Exception as exc:
        log.warning("sitemap blog posts: %s", exc)
    body = "\n".join(
        f"  <url><loc>{loc}</loc><changefreq>{cf}</changefreq><priority>{pr}</priority></url>"
        for loc, cf, pr in urls
    )
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}\n</urlset>"
    )
    return Response(content, media_type="application/xml")
