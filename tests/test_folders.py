"""Tests for folder CRUD endpoints and folder_id on cases."""

from __future__ import annotations

# We test the model logic directly, without spinning up the full app,
# to keep tests fast and free of auth/Playwright dependencies.
from app.models import Case, CaseCreate, Folder, FolderCreate


class TestFolderModel:
    def test_folder_has_required_fields(self):
        f = Folder(id="f1", name="My Folder", created_at="2024-01-01T00:00:00")
        assert f.id == "f1"
        assert f.name == "My Folder"

    def test_folder_create_minimal(self):
        fc = FolderCreate(name="Ops 2024")
        assert fc.name == "Ops 2024"

    def test_folder_dump(self):
        f = Folder(id="x", name="Test", created_at="2024-01-01T00:00:00")
        d = f.model_dump()
        assert d == {"id": "x", "name": "Test", "created_at": "2024-01-01T00:00:00"}


class TestCaseWithFolder:
    def test_case_accepts_folder_id(self):
        c = Case(id="c1", name="My Case", created_at="2024-01-01T00:00:00", folder_id="f1")
        assert c.folder_id == "f1"

    def test_case_folder_id_defaults_to_none(self):
        c = Case(id="c2", name="Orphan", created_at="2024-01-01T00:00:00")
        assert c.folder_id is None

    def test_case_create_accepts_folder_id(self):
        cc = CaseCreate(name="Op Phish", folder_id="folder-abc")
        assert cc.folder_id == "folder-abc"

    def test_case_create_folder_id_optional(self):
        cc = CaseCreate(name="Standalone")
        assert cc.folder_id is None

    def test_case_dump_includes_folder_id(self):
        c = Case(id="c3", name="With Folder", created_at="2024-01-01T00:00:00", folder_id="f-xyz")
        d = c.model_dump()
        assert d["folder_id"] == "f-xyz"

    def test_case_dump_folder_id_none_when_unset(self):
        c = Case(id="c4", name="No Folder", created_at="2024-01-01T00:00:00")
        d = c.model_dump()
        assert d["folder_id"] is None


class TestFolderEndpointLogic:
    """Test the in-memory folder operations without HTTP layer."""

    def test_folders_dict_operations(self):

        folders: dict[str, dict] = {}
        folder = Folder(id="f1", name="Test Folder", created_at="2024-01-01T00:00:00")
        folders[folder.id] = folder
        assert "f1" in folders
        assert folders["f1"].name == "Test Folder"
        folders.pop("f1", None)
        assert "f1" not in folders

    def test_deleting_folder_unlinks_cases(self):
        """Simulate the server-side logic of unlinking cases on folder delete."""
        cases = {
            "c1": Case(id="c1", name="Case 1", created_at="2024-01-01T00:00:00", folder_id="f1"),
            "c2": Case(id="c2", name="Case 2", created_at="2024-01-01T00:00:00", folder_id="f2"),
            "c3": Case(id="c3", name="Case 3", created_at="2024-01-01T00:00:00", folder_id="f1"),
        }
        folder_to_delete = "f1"
        for case in cases.values():
            if case.folder_id == folder_to_delete:
                case.folder_id = None

        assert cases["c1"].folder_id is None
        assert cases["c2"].folder_id == "f2"  # unchanged
        assert cases["c3"].folder_id is None
