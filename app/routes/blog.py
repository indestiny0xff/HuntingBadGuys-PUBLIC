"""Blog API: public read endpoints plus authenticated publish/unpublish."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Query as QParam
from fastapi.responses import JSONResponse

from .. import db as _db_module
from ..auth import get_current_user, require_admin
from ..models import BlogPostCreate, UserInDB
from ..services import blog_svc

log = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/blog/posts")
async def blog_list(
    page: int = QParam(default=1, ge=1),
    limit: int = QParam(default=50, ge=1, le=100),
) -> JSONResponse:
    """Public: list published posts (metadata only, newest first)."""
    posts = await _db_module.get_db().list_published_posts(limit=limit, offset=(page - 1) * limit)
    return JSONResponse({"posts": posts})


@router.get("/api/blog/posts/{slug}")
async def blog_get(slug: str) -> JSONResponse:
    """Public: full published post (rendered HTML)."""
    post = await _db_module.get_db().get_post_by_slug(slug)
    if not post or not post.get("is_published"):
        raise HTTPException(status_code=404, detail="Post not found")
    return JSONResponse(post)


@router.post("/api/blog/posts", status_code=201)
async def blog_create(
    req: BlogPostCreate,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Any authenticated user can publish (or upsert) a blog post from a report."""
    import re

    slug = re.sub(r"[^a-z0-9]+", "-", (req.slug or req.title).lower()).strip("-")[:80]
    if not slug:
        raise HTTPException(status_code=400, detail="A valid title or slug is required")
    db = _db_module.get_db()
    existing = await db.get_post_by_slug(slug)
    post_id = existing["id"] if existing else str(uuid.uuid4())
    post = {
        "id": post_id,
        "slug": slug,
        "is_published": req.is_published,
        "published_at": None,  # COALESCE(NOW()) on insert
        "title": req.title,
        "summary": req.summary,
        "tags": req.tags,
        "case_id": req.case_id,
        "author": current_user.username,
        "body_md": req.body_md,
        "body_html": blog_svc.render_md(req.body_md),
        "stix": req.stix,
        "report_html": req.report_html,
        "graph_svg": req.graph_svg,
        "graph_png": req.graph_png,
    }
    await db.upsert_post(post)
    log.info("[%s] published blog post: %s", current_user.username, slug)
    return JSONResponse({"id": post_id, "slug": slug})


@router.delete("/api/blog/posts/{post_id}")
async def blog_delete(
    post_id: str,
    current_admin: UserInDB = Depends(require_admin),
) -> dict[str, str]:
    await _db_module.get_db().delete_post(post_id)
    return {"status": "ok"}


@router.get("/api/blog/admin/posts")
async def blog_admin_list(
    current_admin: UserInDB = Depends(require_admin),
) -> JSONResponse:
    """Admin: list all posts incl. unpublished."""
    return JSONResponse({"posts": await _db_module.get_db().list_all_posts()})


@router.get("/api/blog/by-case/{case_id}")
async def blog_by_case(
    case_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> JSONResponse:
    """Whether a (published or not) blog post exists for this case — drives the
    report editor's Publish/Unpublish toggle."""
    post = await _db_module.get_db().get_post_by_case(case_id)
    return JSONResponse(post or {})


@router.post("/api/blog/posts/{slug}/unpublish")
async def blog_unpublish(
    slug: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, str]:
    """Any authenticated user can unpublish a post (hide it from the public blog)."""
    ok = await _db_module.get_db().set_post_published(slug, False)
    if not ok:
        raise HTTPException(status_code=404, detail="Post not found")
    log.info("[%s] unpublished blog post: %s", current_user.username, slug)
    return {"status": "ok"}
