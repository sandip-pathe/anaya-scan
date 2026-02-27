"""
Tests for anaya.engine.rule_loader.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from anaya.engine.models import LocalPackSource, RemotePackSource, RulePack
from anaya.engine.rule_loader import RuleLoadError, load_pack, load_pack_directory


class TestLoadPack:
    """Tests for load_pack()."""

    def test_valid_yaml_loads_correctly(self, packs_fixture_dir: Path) -> None:
        pack = load_pack(str(packs_fixture_dir / "test-pack.yml"))
        assert isinstance(pack, RulePack)
        assert pack.manifest.id == "test/sample-pack"
        assert pack.manifest.version == "1.0.0"
        assert len(pack.rules) == 2

    def test_rules_are_typed(self, packs_fixture_dir: Path) -> None:
        pack = load_pack(str(packs_fixture_dir / "test-pack.yml"))
        from anaya.engine.models import PatternRule
        assert all(isinstance(r, PatternRule) for r in pack.rules)

    def test_disabled_rule_loads_without_error(self, tmp_path: Path) -> None:
        pack_data = {
            "manifest": {
                "id": "test/disabled",
                "version": "1.0.0",
                "name": "Test",
                "description": "Test pack",
                "last_updated": "2026-01-01",
            },
            "rules": [
                {
                    "id": "disabled-rule",
                    "name": "Disabled Rule",
                    "type": "pattern",
                    "severity": "HIGH",
                    "enabled": False,
                    "message": "Should not fire",
                    "languages": ["python"],
                    "patterns": ["should_not_match"],
                },
            ],
        }
        pack_file = tmp_path / "disabled.yml"
        pack_file.write_text(yaml.dump(pack_data))
        pack = load_pack(str(pack_file))
        assert pack.rules[0].enabled is False

    def test_missing_required_field_produces_human_readable_error(self, tmp_path: Path) -> None:
        """Missing 'patterns' field on a PatternRule must produce a clear error."""
        pack_data = {
            "manifest": {
                "id": "test/bad",
                "version": "1.0.0",
                "name": "Test",
                "description": "Test",
                "last_updated": "2026-01-01",
            },
            "rules": [
                {
                    "id": "no-hardcoded-key",
                    "name": "Missing Patterns",
                    "type": "pattern",
                    "severity": "HIGH",
                    "message": "Bad",
                    "languages": ["python"],
                    # 'patterns' field intentionally missing
                },
            ],
        }
        pack_file = tmp_path / "bad.yml"
        pack_file.write_text(yaml.dump(pack_data))

        with pytest.raises(RuleLoadError) as exc_info:
            load_pack(str(pack_file))

        error_msg = str(exc_info.value)
        # Must be human-readable, not raw Pydantic traceback
        assert "no-hardcoded-key" in error_msg
        assert "patterns" in error_msg
        assert "validation error" not in error_msg.lower()

    def test_unknown_rule_type_raises_descriptive_error(self, tmp_path: Path) -> None:
        pack_data = {
            "manifest": {
                "id": "test/unknown",
                "version": "1.0.0",
                "name": "Test",
                "description": "Test",
                "last_updated": "2026-01-01",
            },
            "rules": [
                {
                    "id": "bad-type",
                    "name": "Bad Type",
                    "type": "magic",
                    "severity": "HIGH",
                    "message": "Bad",
                },
            ],
        }
        pack_file = tmp_path / "unknown.yml"
        pack_file.write_text(yaml.dump(pack_data))

        with pytest.raises(RuleLoadError, match="unknown type.*magic"):
            load_pack(str(pack_file))

    def test_file_not_found_raises_error(self) -> None:
        with pytest.raises(RuleLoadError, match="not found"):
            load_pack("/nonexistent/path.yml")

    def test_invalid_yaml_raises_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{{invalid yaml: [")
        with pytest.raises(RuleLoadError, match="Invalid YAML"):
            load_pack(str(bad_file))

    def test_missing_manifest_raises_error(self, tmp_path: Path) -> None:
        pack_data = {"rules": []}
        pack_file = tmp_path / "no-manifest.yml"
        pack_file.write_text(yaml.dump(pack_data))
        with pytest.raises(RuleLoadError, match="missing required section.*manifest"):
            load_pack(str(pack_file))


class TestLoadPackDirectory:
    """Tests for load_pack_directory()."""

    def test_loads_all_packs_from_directory(self, packs_fixture_dir: Path) -> None:
        packs = load_pack_directory(str(packs_fixture_dir))
        assert len(packs) >= 1
        assert all(isinstance(p, RulePack) for p in packs)

    def test_skips_pack_yml(self, tmp_path: Path) -> None:
        """_pack.yml files should be skipped."""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()

        # This should be skipped
        (vendor_dir / "_pack.yml").write_text(yaml.dump({
            "id": "vendor/meta",
            "version": "1.0.0",
        }))

        # This should be loaded
        pack_data = {
            "manifest": {
                "id": "vendor/rules",
                "version": "1.0.0",
                "name": "Test",
                "description": "Test",
                "last_updated": "2026-01-01",
            },
            "rules": [],
        }
        (vendor_dir / "rules.yml").write_text(yaml.dump(pack_data))

        packs = load_pack_directory(str(tmp_path))
        assert len(packs) == 1
        assert packs[0].manifest.id == "vendor/rules"

    def test_nonexistent_directory_returns_empty(self) -> None:
        packs = load_pack_directory("/nonexistent/directory")
        assert packs == []


class TestPackSources:
    """Tests for LocalPackSource and RemotePackSource."""

    @pytest.mark.asyncio
    async def test_local_pack_source_loads(self, packs_fixture_dir: Path) -> None:
        source = LocalPackSource(str(packs_fixture_dir))
        packs = await source.load()
        assert len(packs) >= 1
        assert all(isinstance(p, RulePack) for p in packs)

    @pytest.mark.asyncio
    async def test_remote_pack_source_raises_not_implemented(self) -> None:
        source = RemotePackSource("test/pack", "https://example.com", "token")
        with pytest.raises(NotImplementedError, match="not implemented in V1"):
            await source.load()
