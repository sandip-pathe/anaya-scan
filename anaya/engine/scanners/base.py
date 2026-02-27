"""
Abstract base scanner.

All scanners inherit from BaseScanner and implement scan_file().
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from anaya.engine.models import Rule, Violation


# File extension → language name
LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".env": "env",
    ".toml": "toml",
    ".ini": "ini",
    ".conf": "conf",
}


class BaseScanner(ABC):
    """Abstract base for all scanners."""

    @abstractmethod
    def scan_file(
        self,
        file_path: str,
        content: str,
        rules: list[Rule],
        pack_id: str,
    ) -> list[Violation]:
        """
        Scan a single file's content against a list of rules.

        Args:
            file_path: Path to the file (for reporting).
            content: Full text content of the file.
            rules: List of rules to check.
            pack_id: The pack ID prefix for fully qualified rule IDs.

        Returns:
            List of Violation objects found.
        """
        ...

    @staticmethod
    def detect_language(file_path: str) -> str | None:
        """
        Detect language from file extension.

        Returns language name string or None if unknown.
        """
        from pathlib import Path as _Path

        p = _Path(file_path)
        ext = p.suffix.lower()

        # Handle dotfiles like ".env" where name == ".env" and suffix == ".env"
        if not ext and p.name.startswith("."):
            ext = p.name.lower()
        elif not ext:
            return None

        return LANGUAGE_MAP.get(ext)
