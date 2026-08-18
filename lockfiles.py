"""Safe, non-executing parsers for common dependency manifests and lockfiles."""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import Requirement

MAX_LOCKFILE_BYTES = 10_000_000
MAX_DEPENDENCIES = 5_000


@dataclass(frozen=True)
class DependencySpec:
    ecosystem: str
    name: str
    version: str
    exact: bool
    source: str

    def display(self) -> str:
        relation = "==" if self.exact else " "
        return f"{self.ecosystem}:{self.name}{relation}{self.version}".rstrip()


SUPPORTED_NAMES = {
    "requirements.txt", "requirements-dev.txt", "pipfile.lock", "poetry.lock", "uv.lock",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "cargo.lock", "go.sum", "pubspec.lock", "composer.lock", "gemfile.lock",
    "packages.lock.json", "paket.lock", "gradle.lockfile", "package.resolved",
    "podfile.lock", "conan.lock", "vcpkg.json", "pom.xml",
}


def supported_lockfile(path: Path) -> bool:
    name = path.name.lower()
    return name in SUPPORTED_NAMES or name.startswith("requirements") and name.endswith(".txt")


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_LOCKFILE_BYTES:
        raise ValueError(f"{path.name} exceeds the {MAX_LOCKFILE_BYTES // 1_000_000} MB safety limit")
    return path.read_text(encoding="utf-8-sig", errors="strict")


def _add(out: list[DependencySpec], ecosystem: str, name: str, version: object,
         exact: bool, source: str) -> None:
    name, version = str(name).strip(), str(version or "").strip()
    if name and version and not name.startswith(("http:", "https:", "git+", "file:")):
        out.append(DependencySpec(ecosystem, name, version, exact, source))


def _python_requirements(path: Path, raw: str, skipped: list[str]) -> list[DependencySpec]:
    out = []
    for number, original in enumerate(raw.splitlines(), 1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "git+", "http://", "https://")):
            skipped.append(f"line {number}: directive or non-registry source")
            continue
        line = line.split(" #", 1)[0].strip()
        try:
            req = Requirement(line)
        except Exception:
            skipped.append(f"line {number}: invalid Python requirement")
            continue
        if req.url:
            skipped.append(f"line {number}: direct URL source")
            continue
        version = str(req.specifier) or "unversioned"
        exact = bool(re.fullmatch(r"==[^,;*]+", version))
        _add(out, "pypi", req.name, version.removeprefix("==") if exact else version, exact, path.name)
    return out


def _json_lock(path: Path, data: dict, skipped: list[str]) -> list[DependencySpec]:
    out: list[DependencySpec] = []
    name = path.name.lower()
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        for key, value in data.get("packages", {}).items():
            if not key or not isinstance(value, dict):
                continue
            pkg = value.get("name") or key.rsplit("node_modules/", 1)[-1]
            _add(out, "npm", pkg, value.get("version"), True, path.name)
        if not out:
            def walk(values):
                for pkg, value in values.items():
                    if isinstance(value, dict):
                        _add(out, "npm", pkg, value.get("version"), True, path.name)
                        walk(value.get("dependencies", {}))
            walk(data.get("dependencies", {}))
    elif name == "composer.lock":
        for group in ("packages", "packages-dev"):
            for value in data.get(group, []):
                _add(out, "packagist", value.get("name"), value.get("version"), True, path.name)
    elif name == "pipfile.lock":
        for group in ("default", "develop"):
            for pkg, value in data.get(group, {}).items():
                version = value.get("version", "unversioned") if isinstance(value, dict) else value
                exact = isinstance(version, str) and version.startswith("==")
                _add(out, "pypi", pkg, str(version).removeprefix("=="), exact, path.name)
    elif name == "packages.lock.json":
        for framework in data.get("dependencies", {}).values():
            for pkg, value in framework.items():
                version = value.get("resolved") or value.get("requested") if isinstance(value, dict) else value
                _add(out, "nuget", pkg, version, bool(isinstance(value, dict) and value.get("resolved")), path.name)
    elif name == "package.resolved":
        pins = data.get("pins", data.get("object", {}).get("pins", []))
        for pin in pins:
            state = pin.get("state", {})
            _add(out, "swift", pin.get("identity") or pin.get("package"), state.get("version") or state.get("revision"), True, path.name)
    elif name == "vcpkg.json":
        baseline = data.get("builtin-baseline", "manifest-constraint")
        for value in data.get("dependencies", []):
            pkg = value if isinstance(value, str) else value.get("name")
            version = baseline if isinstance(value, str) else next((value[k] for k in ("version", "version>=", "version-string") if k in value), baseline)
            _add(out, "vcpkg", pkg, version, False, path.name)
    elif name == "conan.lock":
        nodes = data.get("graph_lock", data).get("nodes", {})
        for value in nodes.values():
            ref = value.get("ref", "") if isinstance(value, dict) else ""
            match = re.match(r"([^/]+)/([^@#]+)", ref)
            if match:
                _add(out, "conan", match.group(1), match.group(2), True, path.name)
    else:
        skipped.append("unsupported JSON lockfile structure")
    return out


def _toml_lock(path: Path, raw: str) -> list[DependencySpec]:
    data, out = tomllib.loads(raw), []
    ecosystem = "cargo" if path.name.lower() == "cargo.lock" else "pypi"
    for value in data.get("package", []):
        _add(out, ecosystem, value.get("name"), value.get("version"), True, path.name)
    return out


def _maven_manifest(path: Path, raw: str, skipped: list[str]) -> list[DependencySpec]:
    out = []
    root = ET.fromstring(raw)
    properties = {}
    props = root.find("{*}properties")
    if props is not None:
        properties = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in props}
    for dependency in root.findall(".//{*}dependency"):
        group = dependency.findtext("{*}groupId", "").strip()
        artifact = dependency.findtext("{*}artifactId", "").strip()
        version = dependency.findtext("{*}version", "").strip()
        match = re.fullmatch(r"\$\{([^}]+)\}", version)
        if match:
            version = properties.get(match.group(1), version)
        if group and artifact and version:
            exact = not any(marker in version for marker in ("[", "]", "(", ")", ",", "+"))
            _add(out, "maven", f"{group}:{artifact}", version, exact, path.name)
        elif group and artifact:
            skipped.append(f"{group}:{artifact}: version inherited or unresolved")
    return out


def _line_lock(path: Path, raw: str, skipped: list[str]) -> list[DependencySpec]:
    out, name = [], path.name.lower()
    if name == "go.sum":
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                _add(out, "go", parts[0], parts[1].removesuffix("/go.mod"), True, path.name)
    elif name == "gradle.lockfile":
        for line in raw.splitlines():
            match = re.match(r"([^:#=]+):([^:=]+):([^=]+)=", line.strip())
            if match:
                _add(out, "maven", f"{match.group(1)}:{match.group(2)}", match.group(3), True, path.name)
    elif name == "gemfile.lock":
        for line in raw.splitlines():
            match = re.match(r" {4}([^ (]+) \(([^ )]+))", line)
            if match:
                _add(out, "rubygems", match.group(1), match.group(2), True, path.name)
    elif name == "podfile.lock":
        for line in raw.splitlines():
            match = re.match(r"  - ([^ /(:]+)(?:/[^ (:]*)? \(([^)]+)\)", line)
            if match:
                _add(out, "cocoapods", match.group(1), match.group(2), True, path.name)
    elif name == "yarn.lock":
        current = []
        for line in raw.splitlines():
            if line and not line.startswith((" ", "#")) and line.endswith(":"):
                current = [x.strip(' "') for x in line[:-1].split(",")]
            match = re.match(r'\s+version\s+"([^"]+)"', line)
            if match:
                for spec in current:
                    pkg = spec.rsplit("@", 1)[0] if "@" in spec[1:] else spec
                    _add(out, "npm", pkg, match.group(1), True, path.name)
                current = []
    elif name == "pnpm-lock.yaml":
        for line in raw.splitlines():
            match = re.match(r"\s{2,}['\"]?/?((?:@[^/]+/)?[^@:'\"]+)@([^:'\"]+)['\"]?:\s*$", line)
            if match:
                _add(out, "npm", match.group(1), match.group(2).split("(", 1)[0], True, path.name)
    elif name == "pubspec.lock":
        current = None
        for line in raw.splitlines():
            match = re.match(r"  ([A-Za-z0-9_]+):\s*$", line)
            if match:
                current = match.group(1)
            version = re.match(r'\s+version:\s+["\']?([^"\']+)', line)
            if current and version:
                _add(out, "pub", current, version.group(1).strip(), True, path.name); current = None
    elif name == "paket.lock":
        for line in raw.splitlines():
            match = re.match(r"\s{4}([^ ]+) \(([^)]+)\)", line)
            if match:
                _add(out, "nuget", match.group(1), match.group(2), True, path.name)
    else:
        skipped.append("unsupported text lockfile structure")
    return out


def parse_dependency_file(path: Path) -> tuple[list[DependencySpec], list[str]]:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or not supported_lockfile(path):
        raise ValueError(f"Unsupported dependency file: {path.name}")
    raw, skipped = _read(path), []
    name = path.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        out = _python_requirements(path, raw, skipped)
    elif name.endswith(".json") or name in {"pipfile.lock", "package.resolved", "conan.lock"}:
        out = _json_lock(path, json.loads(raw), skipped)
    elif name in {"cargo.lock", "poetry.lock", "uv.lock"}:
        out = _toml_lock(path, raw)
    elif name == "pom.xml":
        out = _maven_manifest(path, raw, skipped)
    else:
        out = _line_lock(path, raw, skipped)
    unique = list(dict.fromkeys(out))
    if len(unique) > MAX_DEPENDENCIES:
        raise ValueError(f"More than {MAX_DEPENDENCIES} dependencies; split the scan")
    if not unique:
        raise ValueError(f"No supported registry dependencies found in {path.name}")
    return unique, skipped
