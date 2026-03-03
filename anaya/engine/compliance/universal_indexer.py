"""
UniversalIndexer — language-agnostic codebase analysis via regex + config parsing.

Unlike the Python-AST-based CodebaseIndexer (Django/FastAPI), this module uses
regex patterns, config-file parsing, and structural heuristics to index codebases
in **any** language/framework:

  - JavaScript / TypeScript (Express, NestJS, Prisma, Sequelize, TypeORM, Mongoose)
  - Java (Spring Boot, JPA/Hibernate)
  - Ruby (Rails / ActiveRecord)
  - Go (Gin, Echo, Fiber, GORM)
  - PHP (Laravel / Eloquent)
  - C# (ASP.NET / Entity Framework)
  - Rust (Actix, Axum, Diesel)
  - Python (fallback if main indexer doesn't detect a framework)

The output is the same CodebaseMap used by every compliance analyzer, so the
downstream pipeline is 100 % language-agnostic.

This file is additive — the original ``indexer.py`` still handles Python/Django
deeply.  ``CodebaseIndexer.build()`` auto-dispatches: Python-primary repos go
through the AST path; everything else goes through this module.

Usage (standalone):
    from anaya.engine.compliance.universal_indexer import UniversalIndexer
    cmap = UniversalIndexer("/path/to/repo").build()
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Iterator

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

# ═════════════════════════════════════════════════════════════════════════════
# Constants
# ═════════════════════════════════════════════════════════════════════════════

# Directories to always skip
_SKIP_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", ".git", "__pycache__",
    ".tox", ".venv", "venv", "env", ".mypy_cache", ".pytest_cache",
    "htmlcov", ".next", ".nuxt", "coverage", "target", "bin", "obj",
    ".gradle", ".idea", ".vscode", "tmp", "temp", "log", "logs",
    "public", "static", "assets", "migrations", ".svn",
})

# File extensions per language family
_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
}

# ═════════════════════════════════════════════════════════════════════════════
# Language / framework detection
# ═════════════════════════════════════════════════════════════════════════════

# package-file → (language, {dependency_name: framework_enum})
_PACKAGE_FILE_FRAMEWORKS: dict[str, tuple[str, dict[str, Framework]]] = {
    "package.json": ("javascript", {
        "express": Framework.EXPRESS,
        "@nestjs/core": Framework.NESTJS,
        "koa": Framework.KOA,
        "fastify": Framework.FASTIFY,
        "hapi": Framework.HAPI,
        "@hapi/hapi": Framework.HAPI,
        "next": Framework.NEXTJS,
    }),
    "pom.xml": ("java", {
        "spring-boot": Framework.SPRING,
        "spring-web": Framework.SPRING,
        "spring-boot-starter-web": Framework.SPRING,
    }),
    "build.gradle": ("java", {
        "spring-boot": Framework.SPRING,
        "org.springframework.boot": Framework.SPRING,
    }),
    "build.gradle.kts": ("java", {
        "spring-boot": Framework.SPRING,
        "org.springframework.boot": Framework.SPRING,
    }),
    "Gemfile": ("ruby", {
        "rails": Framework.RAILS,
        "sinatra": Framework.SINATRA,
    }),
    "go.mod": ("go", {
        "github.com/gin-gonic/gin": Framework.GIN,
        "github.com/labstack/echo": Framework.ECHO,
        "github.com/gofiber/fiber": Framework.FIBER,
    }),
    "composer.json": ("php", {
        "laravel/framework": Framework.LARAVEL,
        "symfony/symfony": Framework.SYMFONY,
        "symfony/framework-bundle": Framework.SYMFONY,
    }),
    "Cargo.toml": ("rust", {
        "actix-web": Framework.ACTIX,
        "axum": Framework.AXUM,
        "rocket": Framework.ROCKET,
    }),
}


def _detect_language_and_framework(root: Path) -> tuple[str, Framework, str | None]:
    """
    Detect primary language and framework from project config files.

    Returns (language, framework, version_or_none).
    """
    # ── Check config files ───────────────────────────────────────────────
    for filename, (lang, fw_map) in _PACKAGE_FILE_FRAMEWORKS.items():
        fpath = root / filename
        if not fpath.exists():
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:
            continue

        for dep_name, fw_enum in fw_map.items():
            if dep_name.lower() in content:
                version = _extract_dep_version(fpath, dep_name)
                return lang, fw_enum, version

    # ── C# — check .csproj files ────────────────────────────────────────
    for csproj in root.rglob("*.csproj"):
        if any(p in _SKIP_DIRS for p in csproj.parts):
            continue
        try:
            content = csproj.read_text(encoding="utf-8", errors="replace").lower()
            if "microsoft.aspnetcore" in content or "aspnet" in content:
                return "csharp", Framework.ASPNET, None
        except Exception:
            pass

    # ── Fallback: count file extensions ──────────────────────────────────
    ext_counts: dict[str, int] = {}
    for p in _walk_source_files(root, limit=2000):
        ext = p.suffix.lower()
        lang = _EXT_LANG.get(ext)
        if lang:
            ext_counts[lang] = ext_counts.get(lang, 0) + 1

    if ext_counts:
        primary_lang = max(ext_counts, key=ext_counts.get)  # type: ignore[arg-type]
        return primary_lang, Framework.UNKNOWN, None

    return "unknown", Framework.UNKNOWN, None


def _extract_dep_version(fpath: Path, dep_name: str) -> str | None:
    """Best-effort version extraction from package files."""
    name = fpath.name
    try:
        content = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    if name == "package.json":
        try:
            data = json.loads(content)
            for section in ("dependencies", "devDependencies"):
                ver = data.get(section, {}).get(dep_name)
                if ver:
                    return ver.lstrip("^~>=<")
        except Exception:
            pass
    else:
        # Regex for version strings near dep_name
        m = re.search(
            re.escape(dep_name) + r'["\s:=]*["\']?([\d]+\.[\d]+[.\d]*)',
            content, re.I,
        )
        if m:
            return m.group(1)
    return None


# ═════════════════════════════════════════════════════════════════════════════
# File walking
# ═════════════════════════════════════════════════════════════════════════════

_SOURCE_EXTS = frozenset(_EXT_LANG.keys()) | {".prisma", ".graphql", ".gql", ".proto"}


def _walk_source_files(root: Path, *, limit: int = 50_000) -> Iterator[Path]:
    """Yield source files under root, skipping irrelevant directories."""
    count = 0
    for path in root.rglob("*"):
        if count >= limit:
            return
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in _SOURCE_EXTS:
            yield path
            count += 1


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _read_safe(path: Path, max_bytes: int = 512_000) -> str:
    """Read a file safely, returning empty string on error."""
    try:
        raw = path.read_bytes()[:max_bytes]
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ═════════════════════════════════════════════════════════════════════════════
# Model extraction — per-language regex patterns
# ═════════════════════════════════════════════════════════════════════════════


class _ModelExtractor:
    """Extract data-model definitions from any language using regex patterns."""

    def __init__(self, root: Path, language: str, framework: Framework) -> None:
        self.root = root
        self.language = language
        self.framework = framework

    def extract(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        # Prisma schema (any JS/TS project)
        prisma_models = self._extract_prisma()
        models.extend(prisma_models)

        # Language-specific extractors
        if self.language in ("javascript", "typescript"):
            m, d = self._extract_js_ts()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "java":
            m, d = self._extract_java()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "ruby":
            m, d = self._extract_ruby()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "go":
            m, d = self._extract_go()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "php":
            m, d = self._extract_php()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "csharp":
            m, d = self._extract_csharp()
            models.extend(m)
            deletes.extend(d)
        elif self.language == "rust":
            m, d = self._extract_rust()
            models.extend(m)
            deletes.extend(d)

        # Deduplicate by model name
        seen: set[str] = set()
        unique: list[ModelDefinition] = []
        for m in models:
            if m.name not in seen:
                seen.add(m.name)
                unique.append(m)

        return unique, deletes

    # ── Prisma (.prisma files — popular across JS/TS/Go/Rust) ────────────

    def _extract_prisma(self) -> list[ModelDefinition]:
        models: list[ModelDefinition] = []
        for path in self.root.rglob("*.prisma"):
            if any(p in _SKIP_DIRS for p in path.parts):
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)
            # Match: model ModelName { ... }
            for match in re.finditer(
                r'^model\s+(\w+)\s*\{([^}]*)\}',
                content, re.MULTILINE | re.DOTALL,
            ):
                name = match.group(1)
                body = match.group(2)
                line = content[:match.start()].count("\n") + 1
                fields = self._parse_prisma_fields(body)
                models.append(ModelDefinition(
                    name=name,
                    file=rel,
                    line=line,
                    base_classes=["PrismaModel"],
                    fields=fields,
                ))
        return models

    def _parse_prisma_fields(self, body: str) -> list[ModelField]:
        fields: list[ModelField] = []
        for line in body.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("@@"):
                continue
            # field_name FieldType? @...
            m = re.match(r'^(\w+)\s+(\w+)(\??)\s*(.*)', line)
            if m:
                fname, ftype, nullable, rest = m.groups()
                if fname in ("id", "@@"):
                    continue
                is_nullable = nullable == "?"
                related = None
                on_delete = None
                if "@relation" in rest:
                    related = ftype
                    del_m = re.search(r'onDelete:\s*(\w+)', rest)
                    if del_m:
                        action = del_m.group(1).upper()
                        for ca in CascadeAction:
                            if ca.value in action:
                                on_delete = ca
                                break
                fields.append(ModelField(
                    name=fname,
                    field_type=ftype,
                    python_type=self._prisma_type_to_generic(ftype),
                    is_nullable=is_nullable,
                    related_model=related,
                    on_delete=on_delete,
                ))
        return fields

    @staticmethod
    def _prisma_type_to_generic(prisma_type: str) -> str:
        mapping = {
            "String": "str", "Int": "int", "Float": "float", "Boolean": "bool",
            "DateTime": "datetime", "Decimal": "Decimal", "BigInt": "int",
            "Json": "Any", "Bytes": "bytes",
        }
        return mapping.get(prisma_type, prisma_type)

    # ── JavaScript / TypeScript ──────────────────────────────────────────

    def _extract_js_ts(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() not in (".js", ".ts", ".jsx", ".tsx"):
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # Sequelize: class User extends Model { ... }
            for m in re.finditer(
                r'class\s+(\w+)\s+extends\s+Model\s*\{',
                content,
            ):
                name = m.group(1)
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_sequelize_fields(content, m.end())
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=["Model"], fields=fields,
                ))

            # Sequelize: ModelName.init({ field: DataTypes.X, ... })
            for m in re.finditer(
                r'(\w+)\.init\s*\(\s*\{([^}]*)\}',
                content, re.DOTALL,
            ):
                name = m.group(1)
                line = content[:m.start()].count("\n") + 1
                fields = self._parse_sequelize_init_fields(m.group(2))
                if fields:
                    models.append(ModelDefinition(
                        name=name, file=rel, line=line,
                        base_classes=["SequelizeModel"], fields=fields,
                    ))

            # TypeORM: @Entity() class User { ... }
            for m in re.finditer(
                r'@Entity\([^)]*\)\s*(?:export\s+)?class\s+(\w+)',
                content,
            ):
                name = m.group(1)
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_typeorm_fields(content, m.end())
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=["TypeORMEntity"], fields=fields,
                ))

            # Mongoose: new Schema({ ... })
            for m in re.finditer(
                r'(?:const|let|var)\s+(\w+)\s*=\s*new\s+(?:mongoose\.)?Schema\s*\(\s*\{([^}]*)\}',
                content, re.DOTALL,
            ):
                schema_var = m.group(1)
                line = content[:m.start()].count("\n") + 1
                fields = self._parse_mongoose_fields(m.group(2))
                # Try to find model name: mongoose.model('Name', schema)
                model_name = schema_var.replace("Schema", "").replace("schema", "") or schema_var
                name_m = re.search(
                    r"mongoose\.model\s*\(\s*['\"](\w+)['\"]",
                    content,
                )
                if name_m:
                    model_name = name_m.group(1)
                models.append(ModelDefinition(
                    name=model_name, file=rel, line=line,
                    base_classes=["MongooseSchema"], fields=fields,
                ))

        return models, deletes

    def _extract_sequelize_fields(self, content: str, class_end: int) -> list[ModelField]:
        """Extract fields from Sequelize class body or .init() call."""
        # Look for the init() call after the class
        init_m = re.search(r'\.init\s*\(\s*\{([^}]*)\}', content[class_end:class_end + 5000], re.DOTALL)
        if init_m:
            return self._parse_sequelize_init_fields(init_m.group(1))
        return []

    def _parse_sequelize_init_fields(self, body: str) -> list[ModelField]:
        fields: list[ModelField] = []
        # Pattern: field_name: { type: DataTypes.X, ... } or field_name: DataTypes.X
        for m in re.finditer(r'(\w+)\s*:\s*(?:\{[^}]*type\s*:\s*DataTypes\.(\w+)|DataTypes\.(\w+))', body):
            fname = m.group(1)
            ftype = m.group(2) or m.group(3) or "STRING"
            nullable = "allowNull: true" in body or "allowNull:true" in body
            fields.append(ModelField(
                name=fname, field_type=f"DataTypes.{ftype}",
                python_type=self._sequelize_type_map(ftype),
                is_nullable=nullable,
            ))
        return fields

    @staticmethod
    def _sequelize_type_map(dtype: str) -> str:
        mapping = {
            "STRING": "str", "TEXT": "str", "INTEGER": "int", "BIGINT": "int",
            "FLOAT": "float", "DOUBLE": "float", "DECIMAL": "Decimal",
            "BOOLEAN": "bool", "DATE": "datetime", "DATEONLY": "date",
            "UUID": "UUID", "JSON": "Any", "JSONB": "Any", "BLOB": "bytes",
            "ENUM": "str", "ARRAY": "list",
        }
        return mapping.get(dtype, dtype)

    def _extract_typeorm_fields(self, content: str, class_start: int) -> list[ModelField]:
        fields: list[ModelField] = []
        # Find the class body (until next class or end of reasonable range)
        body = content[class_start:class_start + 5000]
        # @Column() field_name: type
        for m in re.finditer(r'@Column\([^)]*\)\s*(\w+)\s*[?!]?\s*:\s*(\w+)', body):
            fname, ftype = m.group(1), m.group(2)
            fields.append(ModelField(name=fname, field_type=f"Column<{ftype}>", python_type=ftype))
        # @ManyToOne, @OneToMany, etc.
        for m in re.finditer(r'@(?:ManyToOne|OneToMany|ManyToMany|OneToOne)\([^)]*\)\s*(\w+)', body):
            fields.append(ModelField(name=m.group(1), field_type="Relation"))
        return fields

    def _parse_mongoose_fields(self, body: str) -> list[ModelField]:
        fields: list[ModelField] = []
        for m in re.finditer(r'(\w+)\s*:\s*(?:\{\s*type\s*:\s*(\w+)|(\w+))', body):
            fname = m.group(1)
            ftype = m.group(2) or m.group(3) or "String"
            if fname in ("type", "required", "default", "ref", "unique", "index"):
                continue
            fields.append(ModelField(name=fname, field_type=f"Mongoose.{ftype}", python_type=ftype))
        return fields

    # ── Java (Spring Boot / JPA / Hibernate) ─────────────────────────────

    def _extract_java(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".java":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # @Entity class X { ... }
            for m in re.finditer(
                r'@Entity(?:\([^)]*\))?\s*(?:@Table\([^)]*\)\s*)?'
                r'(?:public\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{',
                content,
            ):
                name = m.group(1)
                base = m.group(2) or ""
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_jpa_fields(content, m.end())
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=[base] if base else ["JpaEntity"],
                    fields=fields,
                ))

        return models, deletes

    def _extract_jpa_fields(self, content: str, class_start: int) -> list[ModelField]:
        fields: list[ModelField] = []
        body = content[class_start:class_start + 8000]
        # private Type fieldName;
        for m in re.finditer(
            r'(?:@Column[^;]*?\s+)?(?:private|protected|public)\s+'
            r'(\w+(?:<[\w<>,\s]+>)?)\s+(\w+)\s*[;=]',
            body,
        ):
            ftype, fname = m.group(1), m.group(2)
            if fname in ("serialVersionUID",):
                continue
            nullable = "@Nullable" in content[max(0, class_start + m.start() - 100):class_start + m.start()]
            is_relation = any(
                ann in content[max(0, class_start + m.start() - 200):class_start + m.start()]
                for ann in ("@ManyToOne", "@OneToMany", "@ManyToMany", "@OneToOne")
            )
            fields.append(ModelField(
                name=fname,
                field_type=ftype,
                python_type=self._java_type_map(ftype),
                is_nullable=nullable,
                related_model=ftype if is_relation else None,
            ))
        return fields

    @staticmethod
    def _java_type_map(jtype: str) -> str:
        base = jtype.split("<")[0].strip()
        mapping = {
            "String": "str", "Integer": "int", "int": "int", "Long": "int",
            "long": "int", "Double": "float", "double": "float", "Float": "float",
            "float": "float", "Boolean": "bool", "boolean": "bool",
            "BigDecimal": "Decimal", "Date": "date", "LocalDate": "date",
            "LocalDateTime": "datetime", "Instant": "datetime", "UUID": "UUID",
            "byte[]": "bytes",
        }
        return mapping.get(base, base)

    # ── Ruby (Rails / ActiveRecord) ──────────────────────────────────────

    def _extract_ruby(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".rb":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # class User < ApplicationRecord / ActiveRecord::Base
            for m in re.finditer(
                r'class\s+(\w+)\s*<\s*(ApplicationRecord|ActiveRecord::Base|\w+)',
                content,
            ):
                name = m.group(1)
                base = m.group(2)
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_rails_fields(content, m.end(), name)
                has_del, del_items = self._extract_rails_associations(
                    content, m.end(), name, rel, line,
                )
                deletes.extend(del_items)
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=[base], fields=fields,
                    has_soft_delete="acts_as_paranoid" in content
                    or "paranoia" in content
                    or "discard" in content,
                ))

        # Also try to parse db/schema.rb for table/column definitions
        schema_path = self.root / "db" / "schema.rb"
        if schema_path.exists():
            schema_models = self._parse_rails_schema(schema_path)
            # Merge: add fields from schema.rb to models that lack fields
            schema_by_name = {m.name: m for m in schema_models}
            existing_names = {m.name for m in models}
            for sm in schema_models:
                if sm.name not in existing_names:
                    models.append(sm)
                else:
                    # Add fields if existing model has none
                    for em in models:
                        if em.name == sm.name and not em.fields:
                            em.fields = sm.fields

        return models, deletes

    def _extract_rails_fields(self, content: str, class_start: int, model_name: str) -> list[ModelField]:
        """Extract from db/schema.rb later — Rails models don't define fields in class."""
        return []

    def _extract_rails_associations(
        self, content: str, class_start: int, model_name: str, file: str, line: int,
    ) -> tuple[bool, list[DeletePath]]:
        deletes: list[DeletePath] = []
        body = content[class_start:class_start + 3000]
        # has_many :comments, dependent: :destroy
        for m in re.finditer(
            r'(?:has_many|has_one|belongs_to)\s+:(\w+)(?:.*?dependent:\s*:(\w+))?',
            body,
        ):
            assoc_name = m.group(1)
            dependent = m.group(2)
            if dependent:
                action = {
                    "destroy": CascadeAction.CASCADE,
                    "delete_all": CascadeAction.CASCADE,
                    "nullify": CascadeAction.SET_NULL,
                    "restrict_with_error": CascadeAction.PROTECT,
                    "restrict_with_exception": CascadeAction.PROTECT,
                }.get(dependent, CascadeAction.UNKNOWN)
                deletes.append(DeletePath(
                    source_model=model_name,
                    field_name=assoc_name,
                    target_model=assoc_name.rstrip("s").title(),
                    on_delete=action,
                    is_blocker=action == CascadeAction.PROTECT,
                    file=file, line=line,
                ))
        return False, deletes

    def _parse_rails_schema(self, schema_path: Path) -> list[ModelDefinition]:
        """Parse db/schema.rb to extract table names and columns."""
        models: list[ModelDefinition] = []
        content = _read_safe(schema_path)
        rel = _rel(self.root, schema_path)

        # create_table "users", ... do |t|
        for table_m in re.finditer(
            r'create_table\s+["\'](\w+)["\'].*?do\s*\|(\w+)\|(.*?)end',
            content, re.DOTALL,
        ):
            table_name = table_m.group(1)
            col_var = table_m.group(2)
            body = table_m.group(3)
            line = content[:table_m.start()].count("\n") + 1

            # Convert table_name to PascalCase model name
            model_name = "".join(
                w.capitalize() for w in table_name.rstrip("s").split("_")
            )

            fields: list[ModelField] = []
            # t.string "email", null: false
            for col_m in re.finditer(
                rf'{re.escape(col_var)}\.(\w+)\s+["\'](\w+)["\']'
                r'(?:.*?null:\s*(true|false))?',
                body,
            ):
                col_type = col_m.group(1)
                col_name = col_m.group(2)
                is_nullable = col_m.group(3) != "false" if col_m.group(3) else True
                fields.append(ModelField(
                    name=col_name,
                    field_type=f"rails.{col_type}",
                    python_type=self._rails_type_map(col_type),
                    is_nullable=is_nullable,
                ))

            models.append(ModelDefinition(
                name=model_name, file=rel, line=line,
                base_classes=["ApplicationRecord"], fields=fields,
            ))

        return models

    @staticmethod
    def _rails_type_map(rails_type: str) -> str:
        mapping = {
            "string": "str", "text": "str", "integer": "int", "bigint": "int",
            "float": "float", "decimal": "Decimal", "boolean": "bool",
            "date": "date", "datetime": "datetime", "timestamp": "datetime",
            "binary": "bytes", "json": "Any", "jsonb": "Any", "uuid": "UUID",
            "inet": "str", "cidr": "str",
        }
        return mapping.get(rails_type, rails_type)

    # ── Go (GORM / struct tags) ──────────────────────────────────────────

    def _extract_go(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".go":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # type User struct { ... }
            for m in re.finditer(
                r'type\s+(\w+)\s+struct\s*\{([^}]*)\}',
                content, re.DOTALL,
            ):
                name = m.group(1)
                body = m.group(2)
                line = content[:m.start()].count("\n") + 1

                # Only include if it has gorm tags or looks like a model
                if 'gorm:' not in body and 'json:' not in body:
                    continue

                fields = self._parse_go_struct_fields(body)
                has_gorm = "gorm.Model" in body or "gorm:" in body
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=["gorm.Model"] if has_gorm else ["struct"],
                    fields=fields,
                ))

        return models, deletes

    def _parse_go_struct_fields(self, body: str) -> list[ModelField]:
        fields: list[ModelField] = []
        for line in body.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            # FieldName FieldType `gorm:"..." json:"..."`
            m = re.match(r'(\w+)\s+([\w.*\[\]]+)', line)
            if m:
                fname, ftype = m.group(1), m.group(2)
                if fname in ("gorm", "Model"):
                    continue
                fields.append(ModelField(
                    name=fname, field_type=ftype,
                    python_type=self._go_type_map(ftype),
                ))
        return fields

    @staticmethod
    def _go_type_map(gotype: str) -> str:
        mapping = {
            "string": "str", "int": "int", "int32": "int", "int64": "int",
            "uint": "int", "uint32": "int", "uint64": "int",
            "float32": "float", "float64": "float", "bool": "bool",
            "time.Time": "datetime", "*time.Time": "datetime",
            "[]byte": "bytes", "uuid.UUID": "UUID",
        }
        return mapping.get(gotype, gotype)

    # ── PHP (Laravel / Eloquent) ─────────────────────────────────────────

    def _extract_php(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".php":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # class User extends Model
            for m in re.finditer(
                r'class\s+(\w+)\s+extends\s+(?:Illuminate\\Database\\Eloquent\\)?Model',
                content,
            ):
                name = m.group(1)
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_laravel_fields(content, m.end())
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=["EloquentModel"], fields=fields,
                    has_soft_delete="SoftDeletes" in content,
                ))

        # Also parse migration files for column defs
        migration_models = self._parse_laravel_migrations()
        model_names = {m.name for m in models}
        for mm in migration_models:
            if mm.name not in model_names:
                models.append(mm)
            else:
                for em in models:
                    if em.name == mm.name and not em.fields:
                        em.fields = mm.fields

        return models, deletes

    def _extract_laravel_fields(self, content: str, class_start: int) -> list[ModelField]:
        fields: list[ModelField] = []
        body = content[class_start:class_start + 5000]
        # $fillable = ['name', 'email', ...]
        fillable_m = re.search(r"\$fillable\s*=\s*\[([^\]]*)\]", body)
        if fillable_m:
            for fm in re.finditer(r"['\"](\w+)['\"]", fillable_m.group(1)):
                fields.append(ModelField(name=fm.group(1), field_type="fillable"))
        # $casts = ['email_verified_at' => 'datetime', ...]
        casts_m = re.search(r"\$casts\s*=\s*\[([^\]]*)\]", body)
        if casts_m:
            for cm in re.finditer(r"['\"](\w+)['\"]\s*=>\s*['\"](\w+)['\"]", casts_m.group(1)):
                # Update existing or add
                fname, ftype = cm.group(1), cm.group(2)
                found = False
                for f in fields:
                    if f.name == fname:
                        f.field_type = ftype
                        found = True
                        break
                if not found:
                    fields.append(ModelField(name=fname, field_type=ftype))
        return fields

    def _parse_laravel_migrations(self) -> list[ModelDefinition]:
        models: list[ModelDefinition] = []
        migrations_dir = self.root / "database" / "migrations"
        if not migrations_dir.is_dir():
            return models
        for path in sorted(migrations_dir.glob("*.php")):
            content = _read_safe(path)
            rel = _rel(self.root, path)
            # Schema::create('users', function (Blueprint $table) { ... })
            for m in re.finditer(
                r"Schema::create\s*\(\s*['\"](\w+)['\"].*?function.*?\{(.*?)\}\s*\)",
                content, re.DOTALL,
            ):
                table_name = m.group(1)
                body = m.group(2)
                line = content[:m.start()].count("\n") + 1
                model_name = "".join(
                    w.capitalize() for w in table_name.rstrip("s").split("_")
                )
                fields: list[ModelField] = []
                # $table->string('email');
                for col_m in re.finditer(
                    r"\$table->(\w+)\s*\(\s*['\"](\w+)['\"]",
                    body,
                ):
                    col_type, col_name = col_m.group(1), col_m.group(2)
                    if col_type in ("index", "unique", "primary", "foreign", "dropColumn"):
                        continue
                    fields.append(ModelField(
                        name=col_name, field_type=f"laravel.{col_type}",
                        python_type=self._laravel_type_map(col_type),
                        is_nullable="->nullable()" in body,
                    ))
                if fields:
                    models.append(ModelDefinition(
                        name=model_name, file=rel, line=line,
                        base_classes=["EloquentModel"], fields=fields,
                    ))
        return models

    @staticmethod
    def _laravel_type_map(ltype: str) -> str:
        mapping = {
            "string": "str", "text": "str", "longText": "str", "mediumText": "str",
            "integer": "int", "bigInteger": "int", "smallInteger": "int",
            "tinyInteger": "int", "unsignedBigInteger": "int",
            "float": "float", "double": "float", "decimal": "Decimal",
            "boolean": "bool", "date": "date", "dateTime": "datetime",
            "timestamp": "datetime", "time": "time", "binary": "bytes",
            "json": "Any", "jsonb": "Any", "uuid": "UUID", "char": "str",
            "enum": "str",
        }
        return mapping.get(ltype, ltype)

    # ── C# (Entity Framework) ───────────────────────────────────────────

    def _extract_csharp(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".cs":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # [Table("...")] or public class X : BaseEntity / DbContext
            for m in re.finditer(
                r'(?:\[Table\([^\]]*\)\]\s*)?'
                r'public\s+class\s+(\w+)(?:\s*:\s*([\w,\s]+))?\s*\{',
                content,
            ):
                name = m.group(1)
                bases = m.group(2) or ""
                # Skip DbContext itself, controllers, etc.
                if any(skip in name for skip in ("DbContext", "Controller", "Startup", "Program")):
                    continue
                line = content[:m.start()].count("\n") + 1
                fields = self._extract_ef_fields(content, m.end())
                if not fields and "DbContext" not in bases:
                    continue
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=[b.strip() for b in bases.split(",") if b.strip()],
                    fields=fields,
                ))

        return models, deletes

    def _extract_ef_fields(self, content: str, class_start: int) -> list[ModelField]:
        fields: list[ModelField] = []
        body = content[class_start:class_start + 5000]
        # public string Email { get; set; }
        for m in re.finditer(
            r'public\s+([\w<>?\[\]]+)\s+(\w+)\s*\{',
            body,
        ):
            ftype, fname = m.group(1), m.group(2)
            if fname in ("Id",) and ftype in ("int", "Guid", "string"):
                continue
            nullable = ftype.endswith("?")
            fields.append(ModelField(
                name=fname, field_type=ftype.rstrip("?"),
                python_type=self._csharp_type_map(ftype.rstrip("?")),
                is_nullable=nullable,
            ))
        return fields

    @staticmethod
    def _csharp_type_map(cstype: str) -> str:
        mapping = {
            "string": "str", "int": "int", "long": "int", "short": "int",
            "double": "float", "float": "float", "decimal": "Decimal",
            "bool": "bool", "DateTime": "datetime", "DateTimeOffset": "datetime",
            "Guid": "UUID", "byte[]": "bytes",
        }
        return mapping.get(cstype, cstype)

    # ── Rust (Diesel / SQLx / SeaORM) ───────────────────────────────────

    def _extract_rust(self) -> tuple[list[ModelDefinition], list[DeletePath]]:
        models: list[ModelDefinition] = []
        deletes: list[DeletePath] = []

        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".rs":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # #[derive(...Queryable...)] struct User { ... }
            for m in re.finditer(
                r'#\[derive\([^)]*(?:Queryable|Insertable|Table|Model|Entity)[^)]*\)\]\s*'
                r'(?:pub\s+)?struct\s+(\w+)\s*\{([^}]*)\}',
                content, re.DOTALL,
            ):
                name = m.group(1)
                body = m.group(2)
                line = content[:m.start()].count("\n") + 1
                fields = self._parse_rust_struct_fields(body)
                models.append(ModelDefinition(
                    name=name, file=rel, line=line,
                    base_classes=["DieselModel"], fields=fields,
                ))

        return models, deletes

    def _parse_rust_struct_fields(self, body: str) -> list[ModelField]:
        fields: list[ModelField] = []
        for m in re.finditer(r'(?:pub\s+)?(\w+)\s*:\s*([\w<>:,\s]+)', body):
            fname, ftype = m.group(1), m.group(2).strip().rstrip(",")
            fields.append(ModelField(
                name=fname, field_type=ftype,
                python_type=self._rust_type_map(ftype),
                is_nullable="Option<" in ftype,
            ))
        return fields

    @staticmethod
    def _rust_type_map(rtype: str) -> str:
        base = rtype.replace("Option<", "").rstrip(">").strip()
        mapping = {
            "String": "str", "i32": "int", "i64": "int", "u32": "int",
            "u64": "int", "f32": "float", "f64": "float", "bool": "bool",
            "NaiveDateTime": "datetime", "NaiveDate": "date",
            "Uuid": "UUID", "Vec<u8>": "bytes",
        }
        return mapping.get(base, base)


# ═════════════════════════════════════════════════════════════════════════════
# Endpoint extraction — per-language regex patterns
# ═════════════════════════════════════════════════════════════════════════════


class _EndpointExtractor:
    """Extract HTTP endpoints / routes from any language using regex patterns."""

    def __init__(
        self, root: Path, language: str, framework: Framework,
        model_names: set[str],
    ) -> None:
        self.root = root
        self.language = language
        self.framework = framework
        self.model_names = model_names

    def extract(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []

        if self.language in ("javascript", "typescript"):
            endpoints.extend(self._extract_express_routes())
            endpoints.extend(self._extract_nestjs_routes())
        elif self.language == "java":
            endpoints.extend(self._extract_spring_routes())
        elif self.language == "ruby":
            endpoints.extend(self._extract_rails_routes())
        elif self.language == "go":
            endpoints.extend(self._extract_go_routes())
        elif self.language == "php":
            endpoints.extend(self._extract_laravel_routes())
        elif self.language == "csharp":
            endpoints.extend(self._extract_aspnet_routes())

        return endpoints

    # ── Express / Koa / Fastify routes ───────────────────────────────────

    def _extract_express_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        method_re = re.compile(
            r'(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*'
            r"""['"](/[^'"]*)['"]\s*""",
            re.I,
        )
        for path in _walk_source_files(self.root):
            if path.suffix.lower() not in (".js", ".ts"):
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)
            for m in method_re.finditer(content):
                http_method = m.group(1).upper()
                url = m.group(2)
                line = content[:m.start()].count("\n") + 1
                method_enum = HttpMethod.ANY if http_method == "ALL" else HttpMethod[http_method]
                endpoints.append(ApiEndpoint(
                    path=url, http_methods=[method_enum],
                    handler=f"route:{url}", file=rel, line=line,
                ))
        return endpoints

    # ── NestJS routes ────────────────────────────────────────────────────

    def _extract_nestjs_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        controller_re = re.compile(
            r"@Controller\s*\(\s*['\"]([^'\"]*)['\"]",
        )
        route_re = re.compile(
            r"@(Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:['\"]([^'\"]*)['\"])?\s*\)",
        )
        for path in _walk_source_files(self.root):
            if path.suffix.lower() not in (".ts", ".js"):
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # Find controller prefix
            prefix = ""
            ctrl_m = controller_re.search(content)
            if ctrl_m:
                prefix = ctrl_m.group(1).strip("/")

            # Find route decorators
            for m in route_re.finditer(content):
                http_method = m.group(1).upper()
                sub_path = m.group(2) or ""
                line = content[:m.start()].count("\n") + 1
                full_path = f"/{prefix}/{sub_path}".rstrip("/") or "/"
                method_enum = HttpMethod.ANY if http_method == "ALL" else HttpMethod[http_method]
                endpoints.append(ApiEndpoint(
                    path=full_path, http_methods=[method_enum],
                    handler=f"controller:{prefix}", file=rel, line=line,
                ))
        return endpoints

    # ── Spring Boot routes ───────────────────────────────────────────────

    def _extract_spring_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        mapping_re = re.compile(
            r'@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\('
            r'[^)]*?(?:value\s*=\s*)?["\']([^"\']*)["\']',
        )
        request_mapping_class_re = re.compile(
            r'@RequestMapping\s*\(\s*["\']([^"\']*)["\']',
        )
        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".java":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            # Class-level @RequestMapping prefix
            prefix = ""
            cls_m = request_mapping_class_re.search(content)
            if cls_m:
                prefix = cls_m.group(1).strip("/")

            for m in mapping_re.finditer(content):
                annotation = m.group(1)
                sub_path = m.group(2)
                line = content[:m.start()].count("\n") + 1
                full_path = f"/{prefix}/{sub_path}".strip("/")
                full_path = f"/{full_path}" if not full_path.startswith("/") else full_path

                method_map = {
                    "GetMapping": HttpMethod.GET,
                    "PostMapping": HttpMethod.POST,
                    "PutMapping": HttpMethod.PUT,
                    "PatchMapping": HttpMethod.PATCH,
                    "DeleteMapping": HttpMethod.DELETE,
                    "RequestMapping": HttpMethod.ANY,
                }
                endpoints.append(ApiEndpoint(
                    path=full_path,
                    http_methods=[method_map.get(annotation, HttpMethod.ANY)],
                    handler=annotation, file=rel, line=line,
                ))
        return endpoints

    # ── Rails routes (config/routes.rb) ──────────────────────────────────

    def _extract_rails_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        routes_path = self.root / "config" / "routes.rb"
        if not routes_path.exists():
            return endpoints
        content = _read_safe(routes_path)
        rel = _rel(self.root, routes_path)

        # resources :users → CRUD endpoints
        for m in re.finditer(r'resources?\s+:(\w+)', content):
            resource = m.group(1)
            line = content[:m.start()].count("\n") + 1
            for method, action in [
                (HttpMethod.GET, "index"), (HttpMethod.GET, "show"),
                (HttpMethod.POST, "create"), (HttpMethod.PUT, "update"),
                (HttpMethod.PATCH, "update"), (HttpMethod.DELETE, "destroy"),
            ]:
                endpoints.append(ApiEndpoint(
                    path=f"/{resource}", http_methods=[method],
                    handler=f"{resource}#{action}", file=rel, line=line,
                ))

        # get/post/put/patch/delete '/path', to: 'controller#action'
        for m in re.finditer(
            r"(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]",
            content, re.I,
        ):
            method_str, path_str = m.group(1).upper(), m.group(2)
            line = content[:m.start()].count("\n") + 1
            endpoints.append(ApiEndpoint(
                path=path_str, http_methods=[HttpMethod[method_str]],
                handler=f"route:{path_str}", file=rel, line=line,
            ))
        return endpoints

    # ── Go routes (Gin / Echo / net/http) ────────────────────────────────

    def _extract_go_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        route_re = re.compile(
            r'(?:\.|\b)(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\s*\(\s*'
            r"""['"](/[^'"]*)['"]\s*""",
            re.I,
        )
        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".go":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)
            for m in route_re.finditer(content):
                method_str = m.group(1).upper()
                url = m.group(2)
                line = content[:m.start()].count("\n") + 1
                if method_str in ("HANDLE", "HANDLEFUNC"):
                    method_enum = HttpMethod.ANY
                else:
                    method_enum = HttpMethod[method_str]
                endpoints.append(ApiEndpoint(
                    path=url, http_methods=[method_enum],
                    handler=f"route:{url}", file=rel, line=line,
                ))
        return endpoints

    # ── Laravel routes (routes/api.php, routes/web.php) ──────────────────

    def _extract_laravel_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        route_files = [
            self.root / "routes" / "api.php",
            self.root / "routes" / "web.php",
        ]
        route_re = re.compile(
            r"Route::(get|post|put|patch|delete|any)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.I,
        )
        resource_re = re.compile(
            r"Route::(?:api)?[Rr]esource\s*\(\s*['\"]([^'\"]+)['\"]",
        )
        for rf in route_files:
            if not rf.exists():
                continue
            content = _read_safe(rf)
            rel = _rel(self.root, rf)

            for m in route_re.finditer(content):
                method_str = m.group(1).upper()
                url = m.group(2)
                line = content[:m.start()].count("\n") + 1
                method_enum = HttpMethod.ANY if method_str == "ANY" else HttpMethod[method_str]
                endpoints.append(ApiEndpoint(
                    path=url, http_methods=[method_enum],
                    handler=f"route:{url}", file=rel, line=line,
                ))

            for m in resource_re.finditer(content):
                resource = m.group(1)
                line = content[:m.start()].count("\n") + 1
                for method in (HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT,
                               HttpMethod.PATCH, HttpMethod.DELETE):
                    endpoints.append(ApiEndpoint(
                        path=f"/{resource}", http_methods=[method],
                        handler=f"resource:{resource}", file=rel, line=line,
                    ))
        return endpoints

    # ── ASP.NET routes (C#) ──────────────────────────────────────────────

    def _extract_aspnet_routes(self) -> list[ApiEndpoint]:
        endpoints: list[ApiEndpoint] = []
        route_re = re.compile(
            r'\[(HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete)'
            r'(?:\(\s*"([^"]*)"\s*\))?\]',
        )
        controller_route_re = re.compile(
            r'\[Route\(\s*"([^"]*)"\s*\)\]',
        )
        for path in _walk_source_files(self.root):
            if path.suffix.lower() != ".cs":
                continue
            content = _read_safe(path)
            rel = _rel(self.root, path)

            prefix = ""
            ctrl_m = controller_route_re.search(content)
            if ctrl_m:
                prefix = ctrl_m.group(1).strip("/")

            for m in route_re.finditer(content):
                annotation = m.group(1)
                sub_path = m.group(2) or ""
                line = content[:m.start()].count("\n") + 1
                full_path = f"/{prefix}/{sub_path}".rstrip("/") or "/"
                method_map = {
                    "HttpGet": HttpMethod.GET, "HttpPost": HttpMethod.POST,
                    "HttpPut": HttpMethod.PUT, "HttpPatch": HttpMethod.PATCH,
                    "HttpDelete": HttpMethod.DELETE,
                }
                endpoints.append(ApiEndpoint(
                    path=full_path,
                    http_methods=[method_map.get(annotation, HttpMethod.ANY)],
                    handler=annotation, file=rel, line=line,
                ))
        return endpoints


# ═════════════════════════════════════════════════════════════════════════════
# Security library / import detection (multi-language)
# ═════════════════════════════════════════════════════════════════════════════

# Pattern: (regex_for_import, category)
_SECURITY_PATTERNS: list[tuple[str, str, str]] = [
    # JavaScript / TypeScript
    (r"""require\s*\(\s*['"]bcrypt['"]\s*\)|from\s+['"]bcrypt['"]""", "hashing", "bcrypt"),
    (r"""require\s*\(\s*['"]argon2['"]\s*\)|from\s+['"]argon2['"]""", "hashing", "argon2"),
    (r"""require\s*\(\s*['"]jsonwebtoken['"]\s*\)|from\s+['"]jsonwebtoken['"]""", "auth", "jsonwebtoken"),
    (r"""require\s*\(\s*['"]passport['"]\s*\)|from\s+['"]passport['"]""", "auth", "passport"),
    (r"""require\s*\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]""", "security", "helmet"),
    (r"""require\s*\(\s*['"]cors['"]\s*\)|from\s+['"]cors['"]""", "security", "cors"),
    (r"""require\s*\(\s*['"]crypto['"]\s*\)|from\s+['"]crypto['"]""", "encryption", "crypto"),
    (r"""require\s*\(\s*['"]winston['"]\s*\)|from\s+['"]winston['"]""", "logging", "winston"),
    (r"""require\s*\(\s*['"]pino['"]\s*\)|from\s+['"]pino['"]""", "logging", "pino"),
    # Java
    (r"import\s+org\.springframework\.security", "auth", "spring-security"),
    (r"import\s+io\.jsonwebtoken", "auth", "jjwt"),
    (r"import\s+javax\.crypto", "encryption", "javax.crypto"),
    (r"import\s+org\.bouncycastle", "encryption", "bouncycastle"),
    (r"import\s+org\.slf4j", "logging", "slf4j"),
    (r"import\s+ch\.qos\.logback", "logging", "logback"),
    # Ruby
    (r"require\s+['\"]bcrypt['\"]", "hashing", "bcrypt"),
    (r"require\s+['\"]jwt['\"]", "auth", "jwt"),
    (r"require\s+['\"]devise['\"]|gem\s+['\"]devise['\"]", "auth", "devise"),
    (r"require\s+['\"]openssl['\"]", "encryption", "openssl"),
    # Go
    (r'"golang\.org/x/crypto"', "encryption", "x/crypto"),
    (r'"github\.com/golang-jwt/jwt"', "auth", "golang-jwt"),
    (r'"go\.uber\.org/zap"', "logging", "zap"),
    (r'"github\.com/sirupsen/logrus"', "logging", "logrus"),
    # PHP
    (r"use\s+Illuminate\\Hashing", "hashing", "laravel-hashing"),
    (r"use\s+Illuminate\\Auth", "auth", "laravel-auth"),
    (r"use\s+Illuminate\\Encryption", "encryption", "laravel-encryption"),
    (r"use\s+Monolog\\", "logging", "monolog"),
    # C#
    (r"using\s+Microsoft\.AspNetCore\.Identity", "auth", "aspnet-identity"),
    (r"using\s+System\.Security\.Cryptography", "encryption", "system-crypto"),
    (r"using\s+Microsoft\.Extensions\.Logging", "logging", "ms-logging"),
    (r"using\s+Serilog", "logging", "serilog"),
]


class _UniversalLibraryExtractor:
    """Detect security-relevant libraries across all languages."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._compiled = [
            (re.compile(pat, re.MULTILINE), cat, name)
            for pat, cat, name in _SECURITY_PATTERNS
        ]

    def extract(self) -> list[LibraryUsage]:
        usages: list[LibraryUsage] = []
        seen: set[tuple[str, str]] = set()

        for path in _walk_source_files(self.root, limit=5000):
            content = _read_safe(path, max_bytes=100_000)
            if not content:
                continue
            rel = _rel(self.root, path)

            for pattern, category, lib_name in self._compiled:
                m = pattern.search(content)
                if m:
                    key = (lib_name, rel)
                    if key not in seen:
                        seen.add(key)
                        line = content[:m.start()].count("\n") + 1
                        usages.append(LibraryUsage(
                            module=lib_name, file=rel, line=line,
                            category=category,
                        ))

        return usages


# ═════════════════════════════════════════════════════════════════════════════
# Git metadata
# ═════════════════════════════════════════════════════════════════════════════


def _get_git_meta(root: Path) -> tuple[str | None, str | None]:
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return sha, branch
    except Exception:
        return None, None


# ═════════════════════════════════════════════════════════════════════════════
# Main UniversalIndexer
# ═════════════════════════════════════════════════════════════════════════════


class UniversalIndexer:
    """
    Language-agnostic codebase indexer using regex + config-file parsing.

    Produces the same CodebaseMap consumed by all compliance analysers.

    Usage:
        indexer = UniversalIndexer("/path/to/any/repo")
        cmap = indexer.build()
    """

    def __init__(self, repo_path: str | Path, *, verbose: bool = False) -> None:
        self.root = Path(repo_path).resolve()
        if not self.root.is_dir():
            raise ValueError(f"Not a directory: {self.root}")
        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    def build(self) -> CodebaseMap:
        """
        Run the full indexing pipeline and return a CodebaseMap.

        Phases (all deterministic, no LLM):
          1. Detect language + framework from config files / file extensions
          2. Extract model definitions (ORM classes, schema files, migrations)
          3. Extract API endpoints (routes, controllers, decorators)
          4. Detect security-relevant library usage
          5. Collect git metadata
          6. Compute summary stats
        """
        logger.info("UniversalIndexer: scanning %s", self.root)

        # ── 1. Language + framework ──────────────────────────────────
        language, framework_enum, version = _detect_language_and_framework(self.root)
        logger.info("Detected: language=%s, framework=%s", language, framework_enum.value)

        framework = FrameworkDetails(
            primary=framework_enum,
            version=version,
        )

        # ── 2. Models ────────────────────────────────────────────────
        model_ext = _ModelExtractor(self.root, language, framework_enum)
        models, delete_paths = model_ext.extract()
        logger.info("Found %d models, %d delete paths", len(models), len(delete_paths))

        # ── 3. Endpoints ─────────────────────────────────────────────
        model_names = {m.name for m in models}
        ep_ext = _EndpointExtractor(self.root, language, framework_enum, model_names)
        endpoints = ep_ext.extract()
        logger.info("Found %d endpoints", len(endpoints))

        # ── 4. Security libraries ────────────────────────────────────
        lib_usages = _UniversalLibraryExtractor(self.root).extract()
        logger.info("Found %d security-relevant imports", len(lib_usages))

        # ── 5. Git metadata ──────────────────────────────────────────
        git_sha, git_branch = _get_git_meta(self.root)

        # ── 6. Assemble ─────────────────────────────────────────────
        cmap = CodebaseMap(
            root=str(self.root),
            git_sha=git_sha,
            git_branch=git_branch,
            framework=framework,
            models=models,
            endpoints=endpoints,
            library_usages=lib_usages,
            delete_paths=delete_paths,
        )
        cmap.compute_stats()
        logger.info("Universal indexing complete. Stats: %s", cmap.stats)
        return cmap
