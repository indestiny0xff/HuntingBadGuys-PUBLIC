"""Tests for the is_private field and privacy filtering logic."""

from __future__ import annotations

from app.models import DomainResult, IPResult


class TestPrivacyModel:
    def test_domain_result_defaults_to_public(self):
        r = DomainResult(target="example.com")
        assert r.is_private is False

    def test_ip_result_defaults_to_public(self):
        r = IPResult(target="1.2.3.4")
        assert r.is_private is False

    def test_domain_result_can_be_private(self):
        r = DomainResult(target="secret.com", is_private=True)
        assert r.is_private is True

    def test_ip_result_can_be_private(self):
        r = IPResult(target="10.0.0.1", is_private=True)
        assert r.is_private is True

    def test_is_private_in_dump(self):
        r = DomainResult(target="example.com")
        d = r.model_dump()
        assert "is_private" in d
        assert d["is_private"] is False

    def test_private_flag_in_dump(self):
        r = DomainResult(target="example.com", is_private=True)
        d = r.model_dump()
        assert d["is_private"] is True


class TestPrivacyFilter:
    """Test saved_only filtering logic (mirrors the server-side list_store filter)."""

    def _make_store(self) -> dict:
        return {
            "id1": {
                "_id": "id1",
                "target": "public.com",
                "kind": "domain",
                "is_private": False,
                "final_status": 200,
            },
            "id2": {
                "_id": "id2",
                "target": "private.com",
                "kind": "domain",
                "is_private": True,
                "final_status": 200,
            },
            "id3": {
                "_id": "id3",
                "target": "1.2.3.4",
                "kind": "ip",
                "is_private": False,
                "final_status": None,
            },
            "id4": {
                "_id": "id4",
                "target": "secret-ip.com",
                "kind": "domain",
                "is_private": True,
                "final_status": 403,
            },
        }

    def test_saved_only_returns_public_items(self):
        store = self._make_store()
        items = [(k, v) for k, v in store.items()]
        saved = [(k, v) for k, v in items if not v.get("is_private", False)]
        assert len(saved) == 2
        targets = [v["target"] for _, v in saved]
        assert "public.com" in targets
        assert "1.2.3.4" in targets

    def test_saved_only_excludes_private_items(self):
        store = self._make_store()
        saved = [v for v in store.values() if not v.get("is_private", False)]
        private_targets = {"private.com", "secret-ip.com"}
        for item in saved:
            assert item["target"] not in private_targets

    def test_all_items_returned_when_no_filter(self):
        store = self._make_store()
        all_items = list(store.values())
        assert len(all_items) == 4

    def test_toggle_privacy_in_memory(self):
        """Simulate the PATCH /store/{id} logic."""
        store = self._make_store()
        item_id = "id1"
        assert store[item_id]["is_private"] is False
        store[item_id]["is_private"] = True
        assert store[item_id]["is_private"] is True

    def test_toggle_privacy_back_to_public(self):
        store = self._make_store()
        item_id = "id2"
        assert store[item_id]["is_private"] is True
        store[item_id]["is_private"] = False
        saved = [v for v in store.values() if not v.get("is_private", False)]
        targets = [v["target"] for v in saved]
        assert "private.com" in targets

    def test_patch_only_updates_allowed_fields(self):
        """Only is_private and case_id should be patchable."""
        store = self._make_store()
        item = store["id1"]
        original_target = item["target"]

        allowed = {"is_private", "case_id"}
        body = {"is_private": True, "kind": "hacked", "target": "evil.com"}
        updates = {k: v for k, v in body.items() if k in allowed}
        item.update(updates)

        assert item["is_private"] is True
        assert item["target"] == original_target  # not overwritten
        assert item["kind"] == "domain"  # not overwritten
