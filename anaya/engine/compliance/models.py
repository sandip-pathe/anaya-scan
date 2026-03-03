"""
Pydantic v2 models for the CodebaseMap — the output of CodebaseIndexer.

All models are serialisable to JSON via .model_dump(mode="json").
No LLM types here, only structural data extracted from AST + grep.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────


class Framework(str, Enum):
    # Python
    DJANGO = "django"
    FASTAPI = "fastapi"
    FLASK = "flask"
    # JavaScript / TypeScript
    EXPRESS = "express"
    NESTJS = "nestjs"
    KOA = "koa"
    HAPI = "hapi"
    FASTIFY = "fastify"
    NEXTJS = "nextjs"
    # Java
    SPRING = "spring"
    # Ruby
    RAILS = "rails"
    SINATRA = "sinatra"
    # Go
    GIN = "gin"
    ECHO = "echo"
    FIBER = "fiber"
    # PHP
    LARAVEL = "laravel"
    SYMFONY = "symfony"
    # C#
    ASPNET = "aspnet"
    # Rust
    ACTIX = "actix"
    AXUM = "axum"
    ROCKET = "rocket"
    # Generic
    UNKNOWN = "unknown"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    ANY = "ANY"


class CascadeAction(str, Enum):
    CASCADE = "CASCADE"
    SET_NULL = "SET_NULL"
    SET_DEFAULT = "SET_DEFAULT"
    PROTECT = "PROTECT"
    DO_NOTHING = "DO_NOTHING"
    RESTRICT = "RESTRICT"
    UNKNOWN = "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Model field
# ─────────────────────────────────────────────────────────────────────────────


class ModelField(BaseModel):
    """A single field on an ORM / schema model."""

    name: str
    field_type: str                        # e.g. "CharField", "IntegerField"
    python_type: str | None = None         # inferred Python type, best-effort
    is_nullable: bool = False
    is_encrypted: bool = False             # True if EncryptedField / custom
    max_length: int | None = None
    related_model: str | None = None       # FK target class name
    on_delete: CascadeAction | None = None # FK cascade action
    extra_kwargs: dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Model definition
# ─────────────────────────────────────────────────────────────────────────────


class ModelDefinition(BaseModel):
    """A class that represents a persistent data model."""

    name: str
    file: str                              # repo-relative path
    line: int                              # line number of class definition
    base_classes: list[str] = Field(default_factory=list)
    fields: list[ModelField] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    has_delete_method: bool = False        # explicit delete() override
    has_soft_delete: bool = False          # is_deleted / deleted_at pattern


# ─────────────────────────────────────────────────────────────────────────────
# API endpoint
# ─────────────────────────────────────────────────────────────────────────────


class EndpointParam(BaseModel):
    name: str
    kind: str    # "path", "query", "body", "header"
    required: bool = True
    annotation: str | None = None


class ApiEndpoint(BaseModel):
    """A single HTTP endpoint in the application."""

    path: str                              # URL pattern, e.g. "/api/patient/"
    http_methods: list[HttpMethod] = Field(default_factory=list)
    handler: str                           # function / ViewSet method name
    file: str
    line: int
    models_read: list[str] = Field(default_factory=list)    # model names
    models_written: list[str] = Field(default_factory=list) # model names
    models_deleted: list[str] = Field(default_factory=list) # model names
    requires_auth: bool = False
    params: list[EndpointParam] = Field(default_factory=list)
    viewset_class: str | None = None       # DRF viewset parent, if any


# ─────────────────────────────────────────────────────────────────────────────
# Security library usage
# ─────────────────────────────────────────────────────────────────────────────


class LibraryUsage(BaseModel):
    """An import of a security-relevant library."""

    module: str                            # e.g. "cryptography.fernet"
    alias: str | None = None
    file: str
    line: int
    category: str                          # "encryption" | "auth" | "logging" | "hashing"


# ─────────────────────────────────────────────────────────────────────────────
# Delete / cascade path
# ─────────────────────────────────────────────────────────────────────────────


class DeletePath(BaseModel):
    """Describes how deletion propagates through model relationships."""

    source_model: str
    field_name: str
    target_model: str
    on_delete: CascadeAction
    is_blocker: bool = False               # True when PROTECT — blocks parent deletion
    file: str
    line: int


# ─────────────────────────────────────────────────────────────────────────────
# Top-level output
# ─────────────────────────────────────────────────────────────────────────────


class FrameworkDetails(BaseModel):
    primary: Framework
    version: str | None = None
    orm: str | None = None                 # "django-orm", "sqlalchemy", "prisma"
    auth_middleware: list[str] = Field(default_factory=list)
    has_drf: bool = False                  # Django REST Framework
    has_celery: bool = False
    has_jwt: bool = False
    has_oauth: bool = False
    global_auth_required: bool = False     # DEFAULT_PERMISSION_CLASSES = IsAuthenticated
    settings_files: list[str] = Field(default_factory=list)


class CodebaseMap(BaseModel):
    """
    The complete structural map of a codebase, produced by CodebaseIndexer.

    This is the input to every section analyser — no LLM has touched it yet.
    """

    # Root path that was indexed (absolute)
    root: str

    # Git metadata (populated if git is available)
    git_sha: str | None = None
    git_branch: str | None = None

    # Detected framework + tooling
    framework: FrameworkDetails

    # All persistent data models found
    models: list[ModelDefinition] = Field(default_factory=list)

    # All HTTP endpoints found
    endpoints: list[ApiEndpoint] = Field(default_factory=list)

    # Security-relevant library imports
    library_usages: list[LibraryUsage] = Field(default_factory=list)

    # FK cascade / delete paths
    delete_paths: list[DeletePath] = Field(default_factory=list)

    # Summary counters (derived, for quick reference)
    stats: dict[str, int] = Field(default_factory=dict)

    # Warnings produced during indexing (non-fatal parse errors, etc.)
    warnings: list[str] = Field(default_factory=list)

    def compute_stats(self) -> None:
        """Populate the stats dict from collected data."""
        self.stats = {
            "total_models": len(self.models),
            "total_fields": sum(len(m.fields) for m in self.models),
            "encrypted_fields": sum(
                1 for m in self.models for f in m.fields if f.is_encrypted
            ),
            "total_endpoints": len(self.endpoints),
            "auth_required_endpoints": sum(
                1 for e in self.endpoints if e.requires_auth
            ),
            "delete_endpoints": sum(
                1 for e in self.endpoints
                if HttpMethod.DELETE in e.http_methods
            ),
            "cascade_delete_paths": sum(
                1 for d in self.delete_paths
                if d.on_delete == CascadeAction.CASCADE
            ),
            "protect_blocker_paths": sum(
                1 for d in self.delete_paths if d.is_blocker
            ),
            "library_usages": len(self.library_usages),
        }
