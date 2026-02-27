"""
CodebaseIndexer — deterministic AST + grep based codebase analysis.

No LLM calls here. This module produces a CodebaseMap that feeds every
section analyser in the compliance pipeline.

Supported frameworks (detection + model/endpoint extraction):
  - Django + DRF (primary)
  - FastAPI (primary)
  - Flask (partial)
  - Others: framework detected, limited model/endpoint extraction

Usage:
    from anaya.engine.compliance.indexer import CodebaseIndexer

    indexer = CodebaseIndexer("/path/to/repo")
    cmap = indexer.build()
    print(cmap.model_dump_json(indent=2))
"""

from __future__ import annotations

import ast
import logging
import re
import subprocess
from pathlib import Path
from typing import Iterator

from anaya.engine.compliance.models import (
    ApiEndpoint,
    CascadeAction,
    CodebaseMap,
    DeletePath,
    EndpointParam,
    Framework,
    FrameworkDetails,
    HttpMethod,
    LibraryUsage,
    ModelDefinition,
    ModelField,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Libraries whose import signals a security-relevant capability
_SECURITY_LIBS: dict[str, str] = {
    # Encryption
    "cryptography": "encryption",
    "fernet": "encryption",
    "nacl": "encryption",
    "pycryptodome": "encryption",
    "pycrypto": "encryption",
    "Crypto": "encryption",
    "django_encrypted_model_fields": "encryption",
    "encrypted_model_fields": "encryption",
    "django_fernet_fields": "encryption",
    "pgcrypto": "encryption",
    "hashids": "hashing",
    # Hashing / passwords
    "bcrypt": "hashing",
    "argon2": "hashing",
    "passlib": "hashing",
    "hashlib": "hashing",
    # Auth
    "jwt": "auth",
    "jose": "auth",
    "authlib": "auth",
    "django.contrib.auth": "auth",
    "rest_framework.authentication": "auth",
    "rest_framework_simplejwt": "auth",
    "oauth2_provider": "auth",
    "social_django": "auth",
    "allauth": "auth",
    "dj_rest_auth": "auth",
    # Logging / audit
    "audit_log": "logging",
    "auditlog": "logging",
    "django_auditlog": "logging",
    "axiom": "logging",
    "sentry_sdk": "logging",
    "structlog": "logging",
    "logging": "logging",
}

# Django field types → inferred Python type (best effort)
_DJANGO_FIELD_PYTHON_TYPES: dict[str, str] = {
    "CharField": "str",
    "TextField": "str",
    "EmailField": "str",
    "URLField": "str",
    "SlugField": "str",
    "UUIDField": "UUID",
    "IntegerField": "int",
    "BigIntegerField": "int",
    "SmallIntegerField": "int",
    "PositiveIntegerField": "int",
    "FloatField": "float",
    "DecimalField": "Decimal",
    "BooleanField": "bool",
    "NullBooleanField": "bool | None",
    "DateField": "date",
    "DateTimeField": "datetime",
    "TimeField": "time",
    "DurationField": "timedelta",
    "BinaryField": "bytes",
    "JSONField": "Any",
    "ArrayField": "list",
    "HStoreField": "dict",
    "ForeignKey": "int",   # FK stores the PK
    "OneToOneField": "int",
    "ManyToManyField": "list",
    "FileField": "str",
    "ImageField": "str",
    "GenericIPAddressField": "str",
    "IPAddressField": "str",
    # Encrypted variants
    "EncryptedCharField": "str",
    "EncryptedTextField": "str",
    "EncryptedEmailField": "str",
    "EncryptedIntegerField": "int",
    "EncryptedDateField": "date",
    "EncryptedDateTimeField": "datetime",
}

_ENCRYPTED_FIELD_NAMES = frozenset(
    k for k in _DJANGO_FIELD_PYTHON_TYPES if k.startswith("Encrypted")
) | {
    "FernetField",
    "pgp_sym_encrypt",
    "EncryptedField",
}

# Regex for on_delete= in Django FK definitions (used as fallback)
_ON_DELETE_RE = re.compile(r"on_delete\s*=\s*models\.(\w+)")

# DRF action → HTTP methods
_DRF_ACTION_METHODS: dict[str, list[HttpMethod]] = {
    "list": [HttpMethod.GET],
    "create": [HttpMethod.POST],
    "retrieve": [HttpMethod.GET],
    "update": [HttpMethod.PUT],
    "partial_update": [HttpMethod.PATCH],
    "destroy": [HttpMethod.DELETE],
}

# Dirs to completely skip
_SKIP_DIRS = frozenset(
    {
        "migrations",
        "__pycache__",
        ".git",
        ".tox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        "htmlcov",
        "docs",
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _rel(root: Path, path: Path) -> str:
    """Return a forward-slash relative path string."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_file(path: Path) -> ast.Module | None:
    """Parse a Python file into an AST, returning None on error."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        logger.debug("Syntax error in %s: %s", path, exc)
        return None
    except Exception as exc:
        logger.debug("Could not parse %s: %s", path, exc)
        return None


def _walk_python_files(root: Path) -> Iterator[Path]:
    """Yield every .py file under root, skipping irrelevant directories."""
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _node_to_str(node: ast.expr | None) -> str:
    """Best-effort stringify an AST expression."""
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _bases(cls: ast.ClassDef) -> list[str]:
    return [_node_to_str(b) for b in cls.bases]


def _get_str_kwarg(call: ast.Call, name: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _get_cascade_action(on_delete_expr: ast.expr | None) -> CascadeAction:
    if on_delete_expr is None:
        return CascadeAction.UNKNOWN
    text = _node_to_str(on_delete_expr).upper()
    for action in CascadeAction:
        if action.value in text:
            return action
    return CascadeAction.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Framework detection
# ─────────────────────────────────────────────────────────────────────────────


class _FrameworkDetector:
    """Detect framework and key tooling from project files."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def detect(self) -> FrameworkDetails:
        # ── Check pyproject.toml / requirements / Pipfile ──────────────────
        deps = self._gather_deps()

        primary = Framework.UNKNOWN
        orm = None
        has_drf = False
        has_celery = "celery" in deps
        has_jwt = any(k in deps for k in ("djangorestframework-simplejwt", "pyjwt", "python-jose"))
        has_oauth = any(k in deps for k in ("django-oauth-toolkit", "authlib", "social-auth-app-django"))
        version = None

        if "django" in deps:
            primary = Framework.DJANGO
            orm = "django-orm"
            version = deps.get("django")
            has_drf = "djangorestframework" in deps
        elif "fastapi" in deps:
            primary = Framework.FASTAPI
            orm = "sqlalchemy" if "sqlalchemy" in deps else (
                "tortoise-orm" if "tortoise-orm" in deps else None
            )
            version = deps.get("fastapi")
        elif "flask" in deps:
            primary = Framework.FLASK
            orm = "sqlalchemy" if "sqlalchemy" in deps else None
            version = deps.get("flask")

        # ── Confirm with file evidence if unknown ───────────────────────────
        if primary == Framework.UNKNOWN:
            primary = self._detect_from_files()

        # ── Find settings files ─────────────────────────────────────────────
        # Match settings*.py OR any .py inside a directory named 'settings'
        settings_paths: set[Path] = set()
        for p in self.root.rglob("settings*.py"):
            if not any(d in _SKIP_DIRS for d in p.parts):
                settings_paths.add(p)
        for p in self.root.rglob("*.py"):
            if "settings" in p.parts and not any(d in _SKIP_DIRS for d in p.parts):
                settings_paths.add(p)
        settings_files = [_rel(self.root, p) for p in sorted(settings_paths)]

        # ── Detect auth middleware from Django settings ─────────────────────
        auth_middleware: list[str] = []
        for sf in settings_files[:8]:
            try:
                content = (self.root / sf).read_text(encoding="utf-8", errors="replace")
                if "SessionAuthentication" in content:
                    auth_middleware.append("SessionAuthentication")
                if "TokenAuthentication" in content:
                    auth_middleware.append("TokenAuthentication")
                if "JWTAuthentication" in content:
                    auth_middleware.append("JWTAuthentication")
                if "BasicAuthentication" in content:
                    auth_middleware.append("BasicAuthentication")
            except Exception:
                pass

        # ── Detect global default permission class (e.g. IsAuthenticated) ──
        global_auth = False
        for sf in settings_files[:8]:
            try:
                content = (self.root / sf).read_text(encoding="utf-8", errors="replace")
                if "IsAuthenticated" in content and "DEFAULT_PERMISSION_CLASSES" in content:
                    global_auth = True
                    break
            except Exception:
                pass

        return FrameworkDetails(
            primary=primary,
            version=version,
            orm=orm,
            auth_middleware=list(dict.fromkeys(auth_middleware)),
            has_drf=has_drf,
            has_celery=has_celery,
            has_jwt=has_jwt,
            has_oauth=has_oauth,
            settings_files=settings_files[:10],
            global_auth_required=global_auth,
        )

    # ── helpers ──────────────────────────────────────────────────────────────

    def _gather_deps(self) -> dict[str, str]:
        """Return {package_name_lowercase: version_or_empty} from dependency files."""
        deps: dict[str, str] = {}
        for fname in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.cfg"):
            fpath = self.root / fname
            if fpath.exists():
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace").lower()
                    # Normalise hyphens→underscores and extract package names
                    for m in re.finditer(r'[\'"]([\w\-\.]+)[\'"]|^([\w\-\.]+)\s*[=><!]', content, re.M):
                        pkg = (m.group(1) or m.group(2) or "").replace("-", "_").strip()
                        if pkg:
                            deps[pkg] = ""
                    # Also do a simple line scan for = version
                    for line in content.splitlines():
                        m = re.match(r'^([\w\-\.]+)\s*[=><!~^]+\s*([\w\.]+)', line.strip())
                        if m:
                            deps[m.group(1).replace("-", "_")] = m.group(2)
                except Exception:
                    pass
        return deps

    def _detect_from_files(self) -> Framework:
        """Fallback: grep a sample of .py files for framework imports."""
        for path in list(self.root.rglob("*.py"))[:200]:
            if any(p in _SKIP_DIRS for p in path.parts):
                continue
            try:
                snippet = path.read_text(encoding="utf-8", errors="replace")[:2000]
                if "from django" in snippet or "import django" in snippet:
                    return Framework.DJANGO
                if "from fastapi" in snippet or "import fastapi" in snippet:
                    return Framework.FASTAPI
                if "from flask" in snippet or "import flask" in snippet:
                    return Framework.FLASK
            except Exception:
                pass
        return Framework.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Django model extractor
# ─────────────────────────────────────────────────────────────────────────────


class _DjangoModelExtractor:
    """Extract ModelDefinition objects from Django model files."""

    def __init__(self, root: Path) -> None:
        self.root = root

    # ── Public ───────────────────────────────────────────────────────────────

    def extract(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []
        for path in _walk_python_files(self.root):
            tree = _parse_file(path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if not self._is_django_model(node):
                    continue
                model_def, fk_deletes = self._extract_model(node, path)
                models.append(model_def)
                deletes.extend(fk_deletes)
        return models, deletes

    # ── Internals ────────────────────────────────────────────────────────────

    # Base class fragments that indicate a non-model class
    _EXCLUDE_BASES = frozenset({
        "ViewSet", "APIView", "GenericAPIView", "GenericViewSet",
        "Serializer", "ModelSerializer", "FilterSet",
        "ModelAdmin", "ImportExportModelAdmin", "ModelResource",
        "RootModel", "ModelForm",
    })

    def _is_django_model(self, cls: ast.ClassDef) -> bool:
        bases = _bases(cls)
        # Exclude pure Pydantic models
        if any("pydantic" in b.lower() for b in bases):
            return False
        # Exclude ViewSets, Serializers, Admin, FilterSets, etc.
        for b in bases:
            for excl in self._EXCLUDE_BASES:
                if excl in b:
                    return False
        patterns = (
            "Model",
            "models.Model",
            "EMRBaseModel",
            "BaseModel",
            "TimestampedModel",
            "SoftDeleteModel",
            "AbstractModel",
        )
        if not any(any(p in b for p in patterns) for b in bases):
            return False
        # Require at least one Django field assignment (models.XField(...))
        # to filter out Pydantic specs / resource classes with 0 fields
        return self._has_django_field(cls)

    def _has_django_field(self, cls: ast.ClassDef) -> bool:
        """Return True if the class body has at least one models.XField() assignment."""
        for item in cls.body:
            if not isinstance(item, ast.Assign):
                continue
            if not isinstance(item.value, ast.Call):
                continue
            func = item.value.func
            # models.CharField(...), models.ForeignKey(...), etc.
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "models":
                    return True
            # Bare field name: CharField(...), ForeignKey(...) — imported directly
            if isinstance(func, ast.Name) and func.id in _DJANGO_FIELD_PYTHON_TYPES:
                return True
        return False

    def _extract_model(
        self, cls: ast.ClassDef, path: Path
    ) -> tuple[ModelDefinition, list[DeletePath]]:
        rel_path = _rel(self.root, path)
        fields: list[ModelField] = []
        fk_deletes: list[DeletePath] = []
        has_delete = False
        has_soft = False
        meta: dict = {}

        for item in cls.body:
            # ── class Meta ─────────────────────────────────────────────────
            if isinstance(item, ast.ClassDef) and item.name == "Meta":
                meta = self._extract_meta(item)
                continue

            # ── method definitions ─────────────────────────────────────────
            if isinstance(item, ast.FunctionDef):
                if item.name == "delete":
                    has_delete = True
                continue

            # ── field assignments (name = models.XField(...)) ──────────────
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if not isinstance(target, ast.Name):
                    continue
                fname = target.id
                if fname.startswith("_"):
                    continue
                fval = item.value
                if not isinstance(fval, ast.Call):
                    continue

                field_type = self._resolve_field_type(fval.func)
                if not field_type:
                    continue

                # Soft-delete heuristic
                if fname in ("is_deleted", "deleted_at", "deleted"):
                    has_soft = True

                # Check encryption
                is_encrypted = field_type in _ENCRYPTED_FIELD_NAMES

                # max_length kwarg
                max_length: int | None = None
                for kw in fval.keywords:
                    if kw.arg == "max_length" and isinstance(kw.value, ast.Constant):
                        try:
                            max_length = int(kw.value.value)
                        except (TypeError, ValueError):
                            pass

                # null= kwarg
                is_nullable = False
                for kw in fval.keywords:
                    if kw.arg in ("null", "blank") and isinstance(kw.value, ast.Constant):
                        is_nullable = bool(kw.value.value)

                # FK specifics
                related_model: str | None = None
                on_delete: CascadeAction | None = None
                if field_type in ("ForeignKey", "OneToOneField", "ManyToManyField"):
                    if fval.args:
                        related_model = _node_to_str(fval.args[0]).strip("'\"")
                    # on_delete keyword
                    for kw in fval.keywords:
                        if kw.arg == "on_delete":
                            on_delete = _get_cascade_action(kw.value)
                    if related_model and on_delete is not None:
                        fk_deletes.append(
                            DeletePath(
                                source_model=cls.name,
                                field_name=fname,
                                target_model=related_model,
                                on_delete=on_delete,
                                is_blocker=on_delete == CascadeAction.PROTECT,
                                file=rel_path,
                                line=item.lineno,
                            )
                        )

                python_type = _DJANGO_FIELD_PYTHON_TYPES.get(field_type)
                if is_nullable and python_type:
                    python_type = f"{python_type} | None"

                extra: dict = {}
                for kw in fval.keywords:
                    if kw.arg not in ("null", "blank", "max_length", "on_delete", "to"):
                        extra[kw.arg] = _node_to_str(kw.value)

                fields.append(
                    ModelField(
                        name=fname,
                        field_type=field_type,
                        python_type=python_type,
                        is_nullable=is_nullable,
                        is_encrypted=is_encrypted,
                        max_length=max_length,
                        related_model=related_model,
                        on_delete=on_delete,
                        extra_kwargs=extra,
                    )
                )

        return (
            ModelDefinition(
                name=cls.name,
                file=rel_path,
                line=cls.lineno,
                base_classes=_bases(cls),
                fields=fields,
                meta=meta,
                has_delete_method=has_delete,
                has_soft_delete=has_soft,
            ),
            fk_deletes,
        )

    def _resolve_field_type(self, func_node: ast.expr) -> str | None:
        """Extract the field class name from an assignment RHS call."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return None

    def _extract_meta(self, meta_cls: ast.ClassDef) -> dict:
        result: dict = {}
        for item in meta_cls.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        try:
                            result[target.id] = ast.literal_eval(item.value)
                        except Exception:
                            result[target.id] = _node_to_str(item.value)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI model extractor (SQLAlchemy / Pydantic schemas)
# ─────────────────────────────────────────────────────────────────────────────


class _FastAPIModelExtractor:
    """Extract ModelDefinition objects from SQLAlchemy ORM models and Pydantic schemas."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def extract(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        for path in _walk_python_files(self.root):
            tree = _parse_file(path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                if not self._is_sa_model(node):
                    continue
                models.append(self._extract_model(node, path))
        return models, []

    def _is_sa_model(self, cls: ast.ClassDef) -> bool:
        bases = _bases(cls)
        sa_patterns = ("Base", "DeclarativeBase", "Model", "db.Model", "SQLModel")
        return any(any(p in b for p in sa_patterns) for b in bases)

    def _extract_model(self, cls: ast.ClassDef, path: Path) -> ModelDefinition:
        rel_path = _rel(self.root, path)
        fields: list[ModelField] = []
        for item in cls.body:
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if not isinstance(target, ast.Name):
                    continue
                fname = target.id
                if fname.startswith("_"):
                    continue
                fval = item.value
                if isinstance(fval, ast.Call):
                    field_type = (
                        fval.func.id
                        if isinstance(fval.func, ast.Name)
                        else getattr(fval.func, "attr", None) or "Column"
                    )
                    fields.append(ModelField(name=fname, field_type=field_type))
                elif isinstance(fval, ast.Subscript):
                    fields.append(
                        ModelField(name=fname, field_type=_node_to_str(fval))
                    )
        return ModelDefinition(
            name=cls.name,
            file=rel_path,
            line=cls.lineno,
            base_classes=_bases(cls),
            fields=fields,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Django URL / DRF viewset endpoint extractor
# ─────────────────────────────────────────────────────────────────────────────


class _DjangoEndpointExtractor:
    """
    Build a list of ApiEndpoint objects by combining:
      1. URL patterns from urls.py files (path(), re_path(), router.register())
      2. ViewSet class analysis (which models are touched, which actions exist)
    """

    def __init__(self, root: Path, model_names: set[str]) -> None:
        self.root = root
        self.model_names = model_names
        # Maps viewset_class_name → ApiEndpoint stubs
        self._viewsets: dict[str, dict] = {}
        self._endpoints: list[ApiEndpoint] = []

    def extract(self) -> list[ApiEndpoint]:
        # Pass 1: collect viewset metadata from viewsets/views files
        for path in _walk_python_files(self.root):
            if not self._is_view_file(path):
                continue
            tree = _parse_file(path)
            if tree is None:
                continue
            self._collect_viewsets(tree, path)

        # Pass 2: collect URL patterns
        for path in _walk_python_files(self.root):
            if not self._is_url_file(path):
                continue
            tree = _parse_file(path)
            if tree is None:
                continue
            self._collect_urls(tree, path)

        return self._endpoints

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_view_file(self, p: Path) -> bool:
        name = p.name.lower()
        return any(
            x in name for x in ("viewset", "view", "api", "serializer", "endpoint")
        )

    def _is_url_file(self, p: Path) -> bool:
        name = p.name.lower()
        return "urls" in name or "router" in name

    def _collect_viewsets(self, tree: ast.Module, path: Path) -> None:
        rel = _rel(self.root, path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases_str = " ".join(_bases(node))
            if not any(
                k in bases_str
                for k in (
                    "ViewSet",
                    "ModelViewSet",
                    "APIView",
                    "GenericAPIView",
                    "ListAPIView",
                    "CreateAPIView",
                    "RetrieveAPIView",
                    "UpdateAPIView",
                    "DestroyAPIView",
                    "RetrieveUpdateDestroyAPIView",
                    "RetrieveUpdateAPIView",
                    "View",
                )
            ):
                continue

            # Determine HTTP methods exposed
            methods: list[HttpMethod] = []
            method_names = {n.name for n in ast.walk(node) if isinstance(n, ast.FunctionDef)}

            # DRF ModelViewSet implicit methods
            if "ModelViewSet" in bases_str:
                methods = list(HttpMethod)
                methods = [m for m in methods if m != HttpMethod.ANY]
            else:
                for method_name, http_methods in _DRF_ACTION_METHODS.items():
                    if method_name in method_names:
                        methods.extend(http_methods)
                for m in ("get", "post", "put", "patch", "delete"):
                    if m in method_names:
                        methods.append(HttpMethod[m.upper()])

            # Deduplicate
            methods = list(dict.fromkeys(methods))

            # Find queryset / model references
            models_touched: list[str] = []
            models_deleted: list[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                    if child.value.id in self.model_names or child.value.id + "s" in self.model_names:
                        if child.value.id not in models_touched:
                            models_touched.append(child.value.id)
                if isinstance(child, ast.Name) and child.id in self.model_names:
                    if child.id not in models_touched:
                        models_touched.append(child.id)

            if HttpMethod.DELETE in methods:
                models_deleted = models_touched[:]

            # Detect auth
            requires_auth = self._has_auth_decorator(node) or self._has_permission_class(node)

            self._viewsets[node.name] = {
                "class_name": node.name,
                "file": rel,
                "line": node.lineno,
                "methods": methods,
                "models_read": models_touched,
                "models_written": models_touched,
                "models_deleted": models_deleted,
                "requires_auth": requires_auth,
                "bases": bases_str,
            }

    def _has_auth_decorator(self, cls: ast.ClassDef) -> bool:
        for dec in cls.decorator_list:
            s = _node_to_str(dec)
            if any(k in s for k in ("permission_required", "login_required", "authentication")):
                return True
        return False

    def _has_permission_class(self, cls: ast.ClassDef) -> bool:
        for item in cls.body:
            if not isinstance(item, ast.Assign):
                continue
            if any(
                isinstance(t, ast.Name) and t.id == "permission_classes"
                for t in item.targets
            ):
                val = _node_to_str(item.value)
                if any(k in val for k in ("IsAuthenticated", "IsAdmin", "AllowAny")):
                    return "AllowAny" not in val
        return False

    def _collect_urls(self, tree: ast.Module, path: Path) -> None:
        rel = _rel(self.root, path)
        for node in ast.walk(tree):
            # router.register("prefix", ViewSetClass, ...)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                func_str = _node_to_str(call.func)
                if func_str.endswith(".register") and call.args:
                    url_prefix = _get_str_kwarg(call, "prefix") or (
                        _node_to_str(call.args[0]).strip("'\"") if call.args else ""
                    )
                    vs_name = _node_to_str(call.args[1]).strip("'\"") if len(call.args) > 1 else ""
                    self._register_viewset_url(url_prefix, vs_name, rel, node.lineno)
                    continue

            # path("...", ViewSet.as_view(), ...)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                for elt in node.value.elts:
                    self._try_extract_path(elt, rel)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.List):
                for elt in node.value.elts:
                    self._try_extract_path(elt, rel)

    def _try_extract_path(self, node: ast.expr, file: str) -> None:
        if not isinstance(node, ast.Call):
            return
        func_name = _node_to_str(node.func)
        if func_name not in ("path", "re_path", "url"):
            return
        if not node.args:
            return

        url = _node_to_str(node.args[0]).strip("'\"")
        if len(node.args) < 2:
            return

        handler_node = node.args[1]
        handler_str = _node_to_str(handler_node)

        # Could be MyViewSet.as_view({...}) or my_function_view
        vs_name = None
        if isinstance(handler_node, ast.Call):
            if isinstance(handler_node.func, ast.Attribute):
                vs_name = _node_to_str(handler_node.func.value)

        if vs_name and vs_name in self._viewsets:
            vs = self._viewsets[vs_name]
            self._endpoints.append(
                ApiEndpoint(
                    path=url,
                    http_methods=vs["methods"],
                    handler=vs_name,
                    file=file,
                    line=node.lineno,
                    models_read=vs["models_read"],
                    models_written=vs["models_written"],
                    models_deleted=vs["models_deleted"],
                    requires_auth=vs["requires_auth"],
                    viewset_class=vs_name,
                )
            )
        else:
            # Function-based view — minimal info
            self._endpoints.append(
                ApiEndpoint(
                    path=url,
                    http_methods=[HttpMethod.ANY],
                    handler=handler_str,
                    file=file,
                    line=node.lineno,
                )
            )

    def _register_viewset_url(
        self, prefix: str, vs_name: str, file: str, line: int
    ) -> None:
        vs = self._viewsets.get(vs_name)
        if vs:
            self._endpoints.append(
                ApiEndpoint(
                    path=f"/{prefix}/",
                    http_methods=vs["methods"],
                    handler=vs_name,
                    file=file,
                    line=line,
                    models_read=vs["models_read"],
                    models_written=vs["models_written"],
                    models_deleted=vs["models_deleted"],
                    requires_auth=vs["requires_auth"],
                    viewset_class=vs_name,
                )
            )
        else:
            self._endpoints.append(
                ApiEndpoint(
                    path=f"/{prefix}/",
                    http_methods=[HttpMethod.GET, HttpMethod.POST,
                                  HttpMethod.PUT, HttpMethod.PATCH,
                                  HttpMethod.DELETE],
                    handler=vs_name,
                    file=file,
                    line=line,
                    viewset_class=vs_name,
                )
            )


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI endpoint extractor
# ─────────────────────────────────────────────────────────────────────────────


class _FastAPIEndpointExtractor:
    """Extract routes from FastAPI apps using @app.get / router.post decorators."""

    def __init__(self, root: Path, model_names: set[str]) -> None:
        self.root = root
        self.model_names = model_names

    def extract(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        http_dec_re = re.compile(
            r"(get|post|put|patch|delete|head|options|trace)", re.I
        )
        for path in _walk_python_files(self.root):
            tree = _parse_file(path)
            if tree is None:
                continue
            rel = _rel(self.root, path)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in node.decorator_list:
                    if not isinstance(dec, ast.Call):
                        continue
                    dec_str = _node_to_str(dec.func)
                    http_m = http_dec_re.search(dec_str)
                    if not http_m:
                        continue
                    method = HttpMethod[http_m.group(1).upper()]
                    url_path = ""
                    if dec.args:
                        url_path = _node_to_str(dec.args[0]).strip("'\"")

                    # Annotate models from return type / params
                    models_read: list[str] = []
                    for arg in node.args.args:
                        ann = _node_to_str(arg.annotation) if arg.annotation else ""
                        for mname in self.model_names:
                            if mname in ann and mname not in models_read:
                                models_read.append(mname)

                    endpoints.append(
                        ApiEndpoint(
                            path=url_path,
                            http_methods=[method],
                            handler=node.name,
                            file=rel,
                            line=node.lineno,
                            models_read=models_read,
                        )
                    )
        return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Security library import extractor
# ─────────────────────────────────────────────────────────────────────────────


class _LibraryImportExtractor:
    """Scan all Python files for security-relevant imports."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def extract(self) -> list[LibraryUsage]:
        usages: list[LibraryUsage] = []
        seen: set[tuple[str, str]] = set()

        for path in _walk_python_files(self.root):
            tree = _parse_file(path)
            if tree is None:
                continue
            rel = _rel(self.root, path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        cat = self._classify(alias.name)
                        if cat:
                            key = (alias.name, rel)
                            if key not in seen:
                                seen.add(key)
                                usages.append(
                                    LibraryUsage(
                                        module=alias.name,
                                        alias=alias.asname,
                                        file=rel,
                                        line=node.lineno,
                                        category=cat,
                                    )
                                )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    cat = self._classify(mod)
                    if cat:
                        key = (mod, rel)
                        if key not in seen:
                            seen.add(key)
                            usages.append(
                                LibraryUsage(
                                    module=mod,
                                    file=rel,
                                    line=node.lineno,
                                    category=cat,
                                )
                            )
        return usages

    def _classify(self, module: str) -> str | None:
        module_lower = module.lower().replace("-", "_")
        for lib, category in _SECURITY_LIBS.items():
            lib_norm = lib.lower().replace("-", "_")
            if module_lower == lib_norm or module_lower.startswith(lib_norm + "."):
                return category
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Git metadata helper
# ─────────────────────────────────────────────────────────────────────────────


def _get_git_meta(root: Path) -> tuple[str | None, str | None]:
    """Return (sha, branch) from git, or (None, None) if not a git repo."""
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return sha, branch
    except Exception:
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Main CodebaseIndexer
# ─────────────────────────────────────────────────────────────────────────────


class CodebaseIndexer:
    """
    Builds a CodebaseMap from a local directory path.

    No LLM calls. Pure AST + file-system analysis.

    Usage:
        indexer = CodebaseIndexer("/path/to/repo")
        cmap = indexer.build()
        print(cmap.model_dump_json(indent=2))
    """

    def __init__(self, repo_path: str | Path, *, verbose: bool = False) -> None:
        self.root = Path(repo_path).resolve()
        if not self.root.is_dir():
            raise ValueError(f"Not a directory: {self.root}")
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        self._warnings: list[str] = []

    # ── Public ───────────────────────────────────────────────────────────────

    def build(self) -> CodebaseMap:
        """
        Run the full indexing pipeline and return a CodebaseMap.

        Phases (all deterministic, no LLM):
          1. Detect framework
          2. Extract model definitions
          3. Extract API endpoints
          4. Extract security library imports
          5. Collect git metadata
          6. Compute summary stats
        """
        logger.info("CodebaseIndexer: starting scan of %s", self.root)

        # ── 1. Framework ──────────────────────────────────────────────────
        framework = _FrameworkDetector(self.root).detect()
        logger.info("Detected framework: %s", framework.primary.value)

        # ── 2. Models ──────────────────────────────────────────────────────
        models: list[ModelDefinition] = []
        delete_paths: list[DeletePath] = []

        if framework.primary == Framework.DJANGO:
            m, d = _DjangoModelExtractor(self.root).extract()
            models, delete_paths = m, d
        elif framework.primary in (Framework.FASTAPI, Framework.FLASK):
            m, d = _FastAPIModelExtractor(self.root).extract()
            models, delete_paths = m, d
        else:
            # Best-effort: try Django extractor first, then FastAPI
            m, d = _DjangoModelExtractor(self.root).extract()
            if not m:
                m, d = _FastAPIModelExtractor(self.root).extract()
            models, delete_paths = m, d

        logger.info("Found %d model classes, %d FK delete paths", len(models), len(delete_paths))

        # ── 3. Endpoints ───────────────────────────────────────────────────
        model_names = {m.name for m in models}
        endpoints: list[ApiEndpoint] = []

        if framework.primary == Framework.DJANGO:
            endpoints = _DjangoEndpointExtractor(self.root, model_names).extract()
        elif framework.primary == Framework.FASTAPI:
            endpoints = _FastAPIEndpointExtractor(self.root, model_names).extract()
        else:
            # Try both
            endpoints = _DjangoEndpointExtractor(self.root, model_names).extract()
            if not endpoints:
                endpoints = _FastAPIEndpointExtractor(self.root, model_names).extract()

        # If there's a global DEFAULT_PERMISSION_CLASSES = IsAuthenticated,
        # mark all endpoints as requiring auth (unless they explicitly have AllowAny).
        if framework.global_auth_required:
            for ep in endpoints:
                if not ep.requires_auth:
                    ep.requires_auth = True

        logger.info("Found %d endpoints", len(endpoints))

        # ── 4. Security imports ────────────────────────────────────────────
        lib_usages = _LibraryImportExtractor(self.root).extract()
        logger.info("Found %d security-relevant imports", len(lib_usages))

        # ── 5. Git metadata ────────────────────────────────────────────────
        git_sha, git_branch = _get_git_meta(self.root)

        # ── 6. Assemble & compute stats ────────────────────────────────────
        cmap = CodebaseMap(
            root=str(self.root),
            git_sha=git_sha,
            git_branch=git_branch,
            framework=framework,
            models=models,
            endpoints=endpoints,
            library_usages=lib_usages,
            delete_paths=delete_paths,
            warnings=self._warnings,
        )
        cmap.compute_stats()
        logger.info("Indexing complete. Stats: %s", cmap.stats)
        return cmap
