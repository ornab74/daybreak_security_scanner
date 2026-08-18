#!/usr/bin/env python3
"""Daybreak Super Scanner: a dependency-free, evidence-first defensive scanner.

Fourteen engines run locally and never execute the target.  Findings are stable,
fingerprinted, baseline-aware, and exportable as text, JSON, HTML, or SARIF.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import json
import math
import os
import re
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

VERSION = "4.1.0"
MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_FILES = 25_000
IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules",
    "vendor", "dist", "build", "target", ".next", ".nuxt", "coverage",
})
TEXT_EXTENSIONS = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".cs", ".php", ".rb",
    ".dart", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp", ".sh",
    ".bash", ".zsh", ".ps1", ".sql", ".graphql", ".yaml", ".yml",
    ".toml", ".json", ".xml", ".ini", ".cfg", ".conf", ".env",
    ".tf", ".tfvars", ".dockerfile", ".gradle", ".properties", ".md",
})
SPECIAL_FILES = frozenset({
    "dockerfile", "gemfile", "pipfile", "requirements.txt", "package.json",
    "package-lock.json", "pyproject.toml", "cargo.toml", "go.mod", "pom.xml",
    "build.gradle", "build.gradle.kts", "composer.json", "pubspec.yaml",
    "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum",
    "pubspec.lock", "composer.lock", "gemfile.lock", "pipfile.lock", "poetry.lock",
    "uv.lock", "packages.lock.json", "paket.lock", "gradle.lockfile",
    "package.resolved", "podfile.lock", "conan.lock", "vcpkg.json",
})
SEVERITY_VALUE = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    engine: str
    rule_id: str
    severity: str
    confidence: float
    title: str
    pattern: re.Pattern[str]
    guidance: str
    extensions: frozenset[str] | None = None


@dataclass
class Finding:
    rule_id: str
    engine: str
    severity: str
    confidence: float
    title: str
    path: str
    line: int
    column: int
    evidence: str
    guidance: str
    fingerprint: str = ""
    suppressed: bool = False

    def finalize(self) -> "Finding":
        identity = f"{self.rule_id}\0{self.path}\0{self.evidence.strip()}"
        self.fingerprint = hashlib.sha256(identity.encode()).hexdigest()[:20]
        return self


def rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def rule(engine: str, rid: str, severity: str, confidence: float, title: str,
         pattern: str, guidance: str, extensions: Iterable[str] | None = None) -> Rule:
    return Rule(engine, rid, severity, confidence, title, rx(pattern), guidance,
                frozenset(extensions) if extensions else None)


# The fourteen engines are intentionally orthogonal. Patterns identify reviewable
# evidence, not proof of exploitability; confidence communicates that distinction.
RULES: tuple[Rule, ...] = (
    # 1. Secrets
    rule("secrets", "DBS001", "critical", .96, "Private key committed",
         r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
         "Revoke the key, remove it from history, and load a replacement from a secret manager."),
    rule("secrets", "DBS002", "high", .93, "Provider credential in source",
         r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{24,})",
         "Revoke and rotate this credential; reference it through a secret manager."),
    rule("secrets", "DBS003", "high", .86, "Hard-coded password or token",
         r"(?:password|passwd|api[_-]?key|secret|access[_-]?token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]",
         "Remove the value, rotate it, and inject it at runtime."),
    # 2. High-entropy tokens (implemented separately)
    # 3. Injection
    rule("injection", "DBS101", "high", .84, "SQL built with string interpolation",
         r"(?:execute|query)\s*\(\s*(?:f['\"]|['\"].*(?:%|\.format\())",
         "Use parameterized queries and bind untrusted values separately."),
    rule("injection", "DBS102", "high", .82, "Dynamic code evaluation",
         r"\b(?:eval|exec)\s*\(", "Replace dynamic evaluation with a strict parser or allowlisted dispatch."),
    # 4. Command execution
    rule("command", "DBS201", "high", .88, "Shell command execution enabled",
         r"\b(?:subprocess\.(?:run|Popen|call|check_output)|child_process\.exec)\s*\([^\n]*(?:shell\s*=\s*True|shell\s*:\s*true)",
         "Pass an argument array with shell mode disabled and validate every external argument."),
    rule("command", "DBS202", "medium", .74, "Direct process shell API",
         r"\b(?:os\.system|Runtime\.getRuntime\(\)\.exec|system|popen)\s*\(",
         "Use a non-shell process API with fixed executable and separated arguments."),
    # 5. Path boundaries
    rule("path", "DBS301", "high", .80, "Archive extraction may permit traversal",
         r"\b(?:extractall|ExtractToDirectory|unpack_archive)\s*\(",
         "Validate every archive member's canonical destination remains below the extraction root."),
    rule("path", "DBS302", "medium", .73, "User input used as a filesystem path",
         r"(?:open|Path|readFile|writeFile)\s*\([^\n]*(?:request|params|query|argv|input\s*\()",
         "Resolve canonically beneath an allowlisted root and reject absolute or escaping paths."),
    # 6. Deserialization
    rule("deserialization", "DBS401", "critical", .91, "Unsafe object deserialization",
         r"\b(?:pickle\.loads?|yaml\.load\s*\(|ObjectInputStream|BinaryFormatter|Marshal\.load)\b",
         "Use a data-only format and schema validation; never deserialize attacker-controlled objects."),
    # 7. Cryptography
    rule("crypto", "DBS501", "high", .90, "Known-weak hash for a security decision",
         r"\b(?:md5|sha1)\s*\(", "Use SHA-256+ for integrity or Argon2id/scrypt/bcrypt for passwords."),
    rule("crypto", "DBS502", "high", .87, "ECB block cipher mode",
         r"\b(?:MODE_ECB|AES/ECB|CipherMode\.ECB)\b", "Use an authenticated mode such as AES-GCM with unique nonces."),
    rule("crypto", "DBS503", "high", .83, "Predictable randomness in security-sensitive code",
         r"\b(?:random\.(?:random|randint|choice)|Math\.random)\s*\(",
         "Use a cryptographically secure random generator for tokens, keys, and nonces."),
    # 8. TLS
    rule("tls", "DBS601", "critical", .95, "TLS certificate validation disabled",
         r"(?:verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)",
         "Restore certificate and hostname verification; configure a trusted CA explicitly if needed."),
    rule("tls", "DBS602", "high", .90, "Obsolete TLS protocol selected",
         r"\b(?:SSLv2|SSLv3|TLSv1(?:_METHOD)?|PROTOCOL_TLSv1)\b",
         "Require TLS 1.2 or newer and remove obsolete protocol fallbacks."),
    # 9. Authentication/session
    rule("auth", "DBS701", "critical", .92, "JWT signature verification disabled",
         r"(?:verify_signature['\"]?\s*[:=]\s*False|algorithms?\s*[:=]\s*\[?['\"]none['\"])",
         "Require an allowlisted algorithm and verify signature, issuer, audience, and expiry."),
    rule("auth", "DBS702", "high", .85, "Session cookie lacks a security attribute",
         r"set_cookie\s*\([^\n]*(?:secure\s*=\s*False|httponly\s*=\s*False|samesite\s*=\s*None)",
         "Set Secure, HttpOnly, and an appropriate SameSite policy."),
    # 10. SSRF/network egress
    rule("ssrf", "DBS801", "high", .79, "Request URL appears attacker-controlled",
         r"(?:requests\.(?:get|post|request)|fetch|http\.(?:Get|Post))\s*\([^\n]*(?:request|params|query|argv|input\s*\()",
         "Allowlist destinations after parsing; block private/link-local ranges and redirect escapes."),
    # 11. Browser output
    rule("xss", "DBS901", "high", .80, "Raw HTML injection sink",
         r"\b(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\b",
         "Render as text or sanitize with a context-aware, maintained HTML sanitizer."),
    # 12. Infrastructure as code
    rule("iac", "DBS1001", "high", .91, "Cloud firewall open to the internet",
         r"(?:cidr_blocks|source_ranges?)\s*=\s*\[[^\]]*['\"]0\.0\.0\.0/0['\"]",
         "Restrict ingress to required source ranges and ports."),
    rule("iac", "DBS1002", "high", .88, "Container runs privileged",
         r"\bprivileged\s*[:=]\s*true\b", "Drop privileged mode and grant only required capabilities."),
    rule("iac", "DBS1003", "medium", .78, "Container image uses a floating latest tag",
         r"\bimage\s*:\s*[^\s:@]+(?::latest)?\s*$", "Pin an immutable image digest and automate controlled updates.", {".yaml", ".yml"}),
    # 13. CI/CD trust
    rule("cicd", "DBS1101", "high", .91, "GitHub Action is not commit-pinned",
         r"\buses\s*:\s*[^\s@]+@(?:main|master|HEAD|v?\d+(?:\.\d+)*)\s*$",
         "Pin third-party actions to a reviewed full commit SHA.", {".yaml", ".yml"}),
    rule("cicd", "DBS1102", "critical", .90, "Untrusted pull-request code may access privileges",
         r"\bpull_request_target\s*:", "Do not checkout or execute untrusted PR code in a privileged workflow.", {".yaml", ".yml"}),
    # 14. Supply-chain/dependencies
    rule("supply-chain", "DBS1201", "high", .89, "Remote script piped to a shell",
         r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
         "Download a versioned artifact, verify its signature/hash, then execute after review."),
    rule("supply-chain", "DBS1202", "high", .82, "Install lifecycle hook executes code",
         r"['\"](?:preinstall|postinstall|prepare)['\"]\s*:\s*['\"]",
         "Remove lifecycle execution or constrain and review the script and its inputs.", {".json"}),
)

ENGINE_DESCRIPTIONS = {
    "secrets": "credential and private-key exposure",
    "entropy": "unknown high-entropy token discovery",
    "injection": "SQL and dynamic-code injection",
    "command": "OS command construction and shell execution",
    "path": "path traversal and unsafe archive extraction",
    "deserialization": "attacker-controlled object reconstruction",
    "crypto": "weak primitives, modes, and randomness",
    "tls": "transport verification and protocol downgrade",
    "auth": "JWT, session, and authentication invariants",
    "ssrf": "attacker-controlled outbound destinations",
    "xss": "browser HTML injection sinks",
    "iac": "cloud, container, and infrastructure exposure",
    "cicd": "workflow privilege and immutable action pinning",
    "supply-chain": "install hooks, remote scripts, and dependency hygiene",
}

# Experimental research directions. These are deliberately labeled as ideas rather
# than findings until each has a measurable validation corpus and false-positive bar.
EXPERIMENTAL_IDEAS: tuple[tuple[str, str], ...] = (
    ("Counterfactual Guard Mining", "Compare sibling handlers to identify the one path missing a normally universal security guard."),
    ("Trust-Boundary Tomography", "Reconstruct layered input-to-privilege boundaries from partial evidence and show where validation becomes thinner."),
    ("Exploit Preconditions Lattice", "Model required attacker capabilities as a lattice so chained weak signals can become one calibrated attack path."),
    ("Invariant Drift Radar", "Learn repeated security invariants across languages and flag implementations that silently diverge from the local norm."),
    ("Negative-Space Diffing", "Detect security checks that disappeared even when renamed or structurally rewritten rather than textually deleted."),
    ("Attacker Budget Scoring", "Estimate exploit cost in requests, timing, access, knowledge, and infrastructure instead of relying on severity labels alone."),
    ("Privilege Half-Life", "Measure how long elevated authority survives after its legitimate operation and locate unnecessarily persistent privilege."),
    ("Dormant Route Awakening", "Find code that becomes externally reachable only under rare feature-flag, plugin, deserialization, or fallback combinations."),
    ("Secret Lineage Graph", "Trace a credential from creation through logs, caches, subprocesses, telemetry, and cleanup to reveal secondary exposure."),
    ("Configuration Contradiction Solver", "Combine application, proxy, cloud, and deployment settings to identify protections canceled by another layer."),
    ("Dependency Capability Delta", "Review upgrades by newly gained capabilities—network, process, filesystem, install hooks—not version numbers alone."),
    ("Semantic Security Checksums", "Fingerprint the meaning of a guard so equivalent refactors remain stable while subtle weakening changes the checksum."),
    ("Remediation Blast-Radius Forecast", "Predict which callers, protocols, and compatibility assumptions a proposed security fix is likely to disturb."),
    ("Security Debt Interest", "Rank weaknesses by expected growth in attack surface as routes, callers, permissions, and dependencies accumulate."),
    ("Patch Immune System", "Generate safe adversarial mutations around a proposed fix and reject patches whose security invariant breaks too easily."),
)


def safe_evidence(line: str, engine: str, width: int = 220) -> str:
    clean = "".join(c for c in line.strip() if c == "\t" or ord(c) >= 32)
    if engine in {"secrets", "entropy"}:
        clean = re.sub(r"(['\"]?)([A-Za-z0-9_+/=-]{8})[A-Za-z0-9_+/=-]{4,}", r"\1\2…<redacted>", clean)
    return clean[:width]


def discover(root: Path, max_files: int) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    notes: list[str] = []
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS and not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS and name.lower() not in SPECIAL_FILES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    notes.append(f"skipped oversized file: {path.relative_to(root)}")
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= max_files:
                notes.append(f"file limit reached ({max_files})")
                return files, notes
    return files, notes


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(ch) / len(value)) * math.log2(value.count(ch) / len(value)) for ch in set(value))


TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/-]{28,118}={0,2}(?![A-Za-z0-9])")


def scan_file(path: Path, root: Path, enabled: frozenset[str]) -> tuple[list[Finding], str | None]:
    try:
        raw = path.read_bytes()
        if b"\x00" in raw:
            return [], f"skipped binary file: {path.relative_to(root)}"
        text = raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return [], f"skipped unreadable file: {path.relative_to(root)} ({type(exc).__name__})"
    rel = path.relative_to(root).as_posix()
    suffix = path.suffix.lower()
    findings: list[Finding] = []
    active_rules = [r for r in RULES if r.engine in enabled and (not r.extensions or suffix in r.extensions)]
    for line_no, line in enumerate(text.splitlines(), 1):
        if "daybreak: ignore" in line.lower():
            continue
        # Raw regex literals are commonly found in scanners, validators, and tests.
        # They describe dangerous syntax but cannot execute it themselves.
        pattern_literal = bool(re.match(r"^\s*(?:[rubf]{0,2})?['\"]", line, re.IGNORECASE))
        if not pattern_literal:
            for current in active_rules:
                match = current.pattern.search(line)
                if match:
                    findings.append(Finding(current.rule_id, current.engine, current.severity,
                        current.confidence, current.title, rel, line_no, match.start() + 1,
                        safe_evidence(line, current.engine), current.guidance).finalize())
        if "entropy" in enabled and not pattern_literal:
            for match in TOKEN_RE.finditer(line):
                token = match.group(0)
                mixed = (bool(re.search(r"[A-Za-z]", token)) and bool(re.search(r"\d", token))) or bool(re.search(r"[+/]", token))
                if mixed and shannon_entropy(token) >= 4.35 and not re.fullmatch(r"[a-fA-F0-9]{40,64}", token):
                    findings.append(Finding("DBS050", "entropy", "medium", .72,
                        "High-entropy token may be a secret", rel, line_no, match.start() + 1,
                        safe_evidence(line, "entropy"),
                        "Confirm whether this is a credential; if so revoke it and use a secret manager.").finalize())
                    break
    return findings, None


def load_baseline(path: Path | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("fingerprints", [])
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise ValueError("baseline must be a JSON list or {\"fingerprints\": [...]}")
    return set(data)


def scan(root: Path, engines: frozenset[str], jobs: int, max_files: int,
         baseline: set[str]) -> tuple[list[Finding], dict]:
    started = time.monotonic()
    files, notes = discover(root, max_files)
    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(scan_file, path, root, engines) for path in files]
        for future in concurrent.futures.as_completed(futures):
            items, note = future.result()
            findings.extend(items)
            if note:
                notes.append(note)
    for item in findings:
        item.suppressed = item.fingerprint in baseline
    findings.sort(key=lambda f: (-SEVERITY_VALUE[f.severity], f.path, f.line, f.rule_id))
    metadata = {
        "scanner": "Daybreak Super Scanner", "version": VERSION,
        "root": root.name, "files_scanned": len(files), "findings": len(findings),
        "active_findings": sum(not f.suppressed for f in findings),
        "elapsed_seconds": round(time.monotonic() - started, 3), "notes": notes[:100],
        "engines": sorted(engines),
    }
    return findings, metadata


def result_document(findings: Sequence[Finding], metadata: dict) -> dict:
    return {"metadata": metadata, "findings": [asdict(f) for f in findings]}


def render_text(findings: Sequence[Finding], metadata: dict, show_suppressed: bool) -> str:
    visible = [f for f in findings if show_suppressed or not f.suppressed]
    out = [f"Daybreak Super Scanner {VERSION}",
           f"Scanned {metadata['files_scanned']} files in {metadata['elapsed_seconds']:.3f}s; {len(visible)} finding(s)."]
    for f in visible:
        marker = " [BASELINED]" if f.suppressed else ""
        out.extend(["", f"{f.severity.upper():8} {f.rule_id} {f.path}:{f.line}:{f.column}{marker}",
                    f"  {f.title} (confidence {f.confidence:.2f})", f"  {f.evidence}", f"  Fix: {f.guidance}",
                    f"  Fingerprint: {f.fingerprint}"])
    for note in metadata["notes"]:
        out.append(f"NOTE: {note}")
    return "\n".join(out) + "\n"


def render_sarif(findings: Sequence[Finding], metadata: dict) -> dict:
    rules = {r.rule_id: r for r in RULES}
    rules["DBS050"] = Rule("entropy", "DBS050", "medium", .72,
        "High-entropy token may be a secret", rx(r"$^"), "Verify and rotate if secret.")
    used = sorted({f.rule_id for f in findings})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "Daybreak Super Scanner", "version": VERSION,
            "informationUri": "https://github.com/", "rules": [{
                "id": rid, "name": re.sub(r"[^A-Za-z0-9]", "", rules[rid].title),
                "shortDescription": {"text": rules[rid].title},
                "help": {"text": rules[rid].guidance},
                "defaultConfiguration": {"level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}[rules[rid].severity]}
            } for rid in used]}},
        "invocations": [{"executionSuccessful": True, "properties": metadata}],
        "results": [{
            "ruleId": f.rule_id,
            "level": "error" if f.severity in {"critical", "high"} else "warning" if f.severity == "medium" else "note",
            "message": {"text": f"{f.title}. {f.guidance}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                "region": {"startLine": f.line, "startColumn": f.column}}}],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
            "suppressions": ([{"kind": "external", "justification": "baseline"}] if f.suppressed else [])
        } for f in findings]
    }]}


def render_html(findings: Sequence[Finding], metadata: dict) -> str:
    rows = []
    for f in findings:
        rows.append("<tr><td class='%s'>%s</td><td>%s</td><td><code>%s:%d</code></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
            f.severity, html.escape(f.severity.upper()), html.escape(f.rule_id), html.escape(f.path), f.line,
            html.escape(f.title), html.escape(f.evidence), html.escape(f.guidance)))
    payload = html.escape(json.dumps(metadata, indent=2))
    return f"""<!doctype html><meta charset='utf-8'><title>Daybreak scan</title>
<style>body{{font:14px system-ui;margin:2rem;background:#10151c;color:#e8eef7}}table{{border-collapse:collapse;width:100%}}th,td{{padding:.6rem;border:1px solid #34404f;text-align:left;vertical-align:top}}code,pre{{white-space:pre-wrap}}.critical{{color:#ff657a}}.high{{color:#ff9f5b}}.medium{{color:#ffd166}}</style>
<h1>Daybreak Super Scanner</h1><pre>{payload}</pre><table><thead><tr><th>Risk</th><th>Rule</th><th>Location</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"""


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evidence-first local security scanner with 14 engines.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--cli", action="store_true", help="run the automation-friendly command-line interface")
    modes.add_argument("--tui", action="store_true", help="open the interactive terminal dashboard")
    modes.add_argument("--gui", action="store_true", help="open the CustomTkinter layered AI interface")
    parser.add_argument("target", nargs="?", default=".", help="directory to scan (default: current directory)")
    parser.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text")
    parser.add_argument("--output", type=Path, help="write report atomically to this file")
    parser.add_argument("--severity", choices=tuple(SEVERITY_VALUE), default="medium", help="minimum reported severity")
    parser.add_argument("--confidence", type=float, default=0.0, help="minimum finding confidence, from 0.0 to 1.0")
    parser.add_argument("--engines", help="comma-separated engine allowlist")
    parser.add_argument("--exclude-engines", default="", help="comma-separated engine denylist")
    parser.add_argument("--baseline", type=Path, help="JSON baseline of accepted fingerprints")
    parser.add_argument("--write-baseline", type=Path, help="write current fingerprints and exit successfully")
    parser.add_argument("--show-suppressed", action="store_true")
    parser.add_argument("--jobs", type=int, default=min(32, (os.cpu_count() or 2) + 4))
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high")
    parser.add_argument("--list-engines", action="store_true")
    parser.add_argument("--list-ideas", action="store_true", help="show 15 experimental high-potential research directions")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args(argv)


def configured_scan(args: argparse.Namespace) -> tuple[Path, list[Finding], dict]:
    if args.jobs < 1 or args.jobs > 128 or args.max_files < 1 or not 0.0 <= args.confidence <= 1.0:
        raise ValueError("--jobs must be 1..128, --max-files positive, and --confidence 0.0..1.0")
    target = Path(args.target).expanduser()
    root = target.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("target is not a directory")
    known = frozenset(ENGINE_DESCRIPTIONS)
    selected = frozenset(x.strip() for x in args.engines.split(",") if x.strip()) if args.engines else known
    excluded = frozenset(x.strip() for x in args.exclude_engines.split(",") if x.strip())
    unknown = (selected | excluded) - known
    if unknown:
        raise ValueError("unknown engine(s): " + ", ".join(sorted(unknown)))
    selected -= excluded
    baseline = load_baseline(args.baseline)
    findings, metadata = scan(root, selected, args.jobs, args.max_files, baseline)
    return root, findings, metadata


def run_cli(args: argparse.Namespace) -> int:
    try:
        _, findings, metadata = configured_scan(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITY_VALUE[args.severity]
    findings = [f for f in findings if SEVERITY_VALUE[f.severity] >= threshold and f.confidence >= args.confidence]
    metadata["findings_after_severity_filter"] = len(findings)
    if args.write_baseline:
        atomic_write(args.write_baseline, json.dumps({"version": 1, "fingerprints": sorted({f.fingerprint for f in findings})}, indent=2) + "\n")
        print(f"Wrote {len(findings)} fingerprints to {args.write_baseline}")
        return 0
    if args.format == "text":
        output = render_text(findings, metadata, args.show_suppressed)
    elif args.format == "json":
        output = json.dumps(result_document(findings, metadata), indent=2) + "\n"
    elif args.format == "sarif":
        output = json.dumps(render_sarif(findings, metadata), indent=2) + "\n"
    else:
        output = render_html(findings, metadata)
    if args.output:
        atomic_write(args.output, output)
        print(f"Wrote {args.format.upper()} report to {args.output}")
    else:
        print(output, end="")
    active = [f for f in findings if not f.suppressed]
    if args.fail_on != "none" and any(SEVERITY_VALUE[f.severity] >= SEVERITY_VALUE[args.fail_on] for f in active):
        return 1
    return 0


def _clip(value: object, width: int) -> str:
    text = str(value).replace("\n", " ")
    return text if len(text) <= width else text[:max(0, width - 1)] + "…"


def _tui_add(screen, row: int, col: int, value: object, attr: int = 0) -> None:
    height, width = screen.getmaxyx()
    if 0 <= row < height and col < width:
        try:
            screen.addstr(row, col, _clip(value, max(0, width - col - 1)), attr)
        except Exception:
            pass


def run_tui(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("error: --tui requires an interactive terminal; use --cli for automation", file=sys.stderr)
        return 2
    try:
        import curses
    except ImportError:
        print("error: this Python build does not include curses; use --cli", file=sys.stderr)
        return 2

    def dashboard(screen) -> int:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        try:
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_CYAN)
        except curses.error:
            pass
        colors = {"critical": curses.color_pair(2) | curses.A_BOLD,
                  "high": curses.color_pair(2), "medium": curses.color_pair(3),
                  "low": curses.color_pair(4), "info": curses.A_DIM}
        selected_index = 0
        offset = 0
        severity_index = list(SEVERITY_VALUE).index(args.severity)
        confidence = args.confidence
        search_query = ""
        sort_mode = "severity"
        show_suppressed = args.show_suppressed
        message = ""
        root: Path | None = None
        all_findings: list[Finding] = []
        metadata: dict = {}

        def rescan() -> None:
            nonlocal root, all_findings, metadata, selected_index, offset, message
            screen.erase()
            _tui_add(screen, 0, 0, " DAYBREAK SUPER SCANNER ", curses.color_pair(5) | curses.A_BOLD)
            _tui_add(screen, 2, 2, f"Scanning {args.target} with 14 evidence engines…", curses.A_BOLD)
            screen.refresh()
            try:
                root, all_findings, metadata = configured_scan(args)
                selected_index = offset = 0
                message = f"Scan completed in {metadata['elapsed_seconds']:.3f}s"
            except Exception as exc:
                root, all_findings, metadata = None, [], {}
                message = f"Scan failed: {exc}"

        def visible() -> list[Finding]:
            threshold = SEVERITY_VALUE[list(SEVERITY_VALUE)[severity_index]]
            items = [f for f in all_findings if SEVERITY_VALUE[f.severity] >= threshold
                     and f.confidence >= confidence and (show_suppressed or not f.suppressed)]
            if search_query:
                needle = search_query.casefold()
                items = [f for f in items if needle in " ".join((f.path, f.title, f.rule_id, f.engine, f.evidence)).casefold()]
            if sort_mode == "location":
                items.sort(key=lambda f: (f.path, f.line, f.column, f.rule_id))
            elif sort_mode == "engine":
                items.sort(key=lambda f: (f.engine, -SEVERITY_VALUE[f.severity], f.path, f.line))
            else:
                items.sort(key=lambda f: (-SEVERITY_VALUE[f.severity], -f.confidence, f.path, f.line))
            return items

        def export(report_format: str) -> None:
            nonlocal message
            if root is None:
                return
            stamp = time.strftime("%Y%m%d-%H%M%S")
            destination = Path.cwd() / f"daybreak-{stamp}.{report_format}"
            document = render_sarif(visible(), metadata) if report_format == "sarif" else result_document(visible(), metadata)
            atomic_write(destination, json.dumps(document, indent=2) + "\n")
            message = f"Exported {destination}"

        def source_context(finding: Finding, radius: int = 2) -> list[str]:
            if root is None:
                return []
            try:
                path = (root / finding.path).resolve(strict=True)
                path.relative_to(root)
                if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                    return []
                lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
            except (OSError, UnicodeError, ValueError):
                return []
            start, end = max(1, finding.line - radius), min(len(lines), finding.line + radius)
            return [f"{'>' if number == finding.line else ' '} {number:5} │ {safe_evidence(lines[number - 1], finding.engine, 500)}"
                    for number in range(start, end + 1)]

        def prompt_search() -> None:
            nonlocal search_query, selected_index, offset, message
            height, width = screen.getmaxyx()
            try:
                curses.echo()
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
                screen.move(height - 1, 0)
                screen.clrtoeol()
                _tui_add(screen, height - 1, 0, "Search (empty clears): ", curses.A_BOLD)
                raw = screen.getstr(height - 1, 23, max(1, width - 25))
                search_query = raw.decode("utf-8", errors="replace").strip()
                selected_index = offset = 0
                message = f"Search: {search_query}" if search_query else "Search cleared"
            finally:
                curses.noecho()
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass

        rescan()
        while True:
            screen.erase()
            height, width = screen.getmaxyx()
            items = visible()
            selected_index = max(0, min(selected_index, max(0, len(items) - 1)))
            list_width = width if width < 100 else max(52, width // 2)
            _tui_add(screen, 0, 0, " DAYBREAK SUPER SCANNER ", curses.color_pair(5) | curses.A_BOLD)
            _tui_add(screen, 0, 27, f"TUI  v{VERSION}", curses.A_BOLD)
            location = str(root) if root else str(args.target)
            _tui_add(screen, 1, 1, f"Target: {location}")
            counts = {s: sum(f.severity == s and not f.suppressed for f in all_findings) for s in SEVERITY_VALUE}
            summary = "  ".join(f"{s[0].upper()}:{counts[s]}" for s in ("critical", "high", "medium", "low", "info"))
            _tui_add(screen, 2, 1, f"Files: {metadata.get('files_scanned', 0)}  Findings: {len(all_findings)}  {summary}")
            minimum = list(SEVERITY_VALUE)[severity_index]
            filters = f"Filter ≥ {minimum.upper()} · conf ≥ {confidence:.2f} · sort {sort_mode}"
            if search_query:
                filters += f" · search {search_query!r}"
            _tui_add(screen, 3, 1, f"{filters}  Showing {len(items)}", curses.color_pair(1) | curses.A_BOLD)
            _tui_add(screen, 4, 1, "SEVERITY  RULE      LOCATION", curses.A_UNDERLINE)
            page_rows = max(1, height - 7)
            if selected_index < offset:
                offset = selected_index
            elif selected_index >= offset + page_rows:
                offset = selected_index - page_rows + 1
            for display_row, finding in enumerate(items[offset:offset + page_rows], 5):
                absolute = offset + display_row - 5
                marker = ">" if absolute == selected_index else " "
                location_text = f"{finding.path}:{finding.line}"
                row_text = f"{marker} {finding.severity.upper():8} {finding.rule_id:9} {_clip(location_text, list_width - 23)}"
                attr = colors.get(finding.severity, 0)
                if absolute == selected_index:
                    attr |= curses.A_REVERSE
                _tui_add(screen, display_row, 0, row_text, attr)
            if width >= 100:
                divider = list_width
                for row in range(4, max(4, height - 1)):
                    _tui_add(screen, row, divider, "│", curses.A_DIM)
                if items:
                    finding = items[selected_index]
                    detail_width = max(20, width - divider - 3)
                    detail = [
                        f"{finding.severity.upper()} · {finding.rule_id} · {finding.engine}", "",
                        finding.title, "", f"Location: {finding.path}:{finding.line}:{finding.column}",
                        f"Confidence: {finding.confidence:.2f}", f"Fingerprint: {finding.fingerprint}", "",
                        "Evidence:", finding.evidence, "", "Recommended remediation:", finding.guidance,
                    ]
                    context = source_context(finding)
                    if context:
                        detail.extend(["", "Source context:", *context])
                    row = 4
                    for paragraph in detail:
                        wrapped = textwrap.wrap(paragraph, detail_width) or [""]
                        for line in wrapped:
                            if row >= height - 2:
                                break
                            _tui_add(screen, row, divider + 2, line, curses.A_BOLD if row == 4 else 0)
                            row += 1
            footer = "j/k move  / search  s severity  c confidence  o sort  b baseline  e/E export  r rescan  q quit"
            _tui_add(screen, height - 2, 0, " " + footer, curses.color_pair(5))
            _tui_add(screen, height - 1, 1, message, curses.A_DIM)
            screen.refresh()
            key = screen.getch()
            message = ""
            if key in (ord("q"), 27):
                return 0
            if key in (curses.KEY_DOWN, ord("j")) and selected_index + 1 < len(items):
                selected_index += 1
            elif key in (curses.KEY_UP, ord("k")) and selected_index > 0:
                selected_index -= 1
            elif key == curses.KEY_NPAGE:
                selected_index = min(max(0, len(items) - 1), selected_index + page_rows)
            elif key == curses.KEY_PPAGE:
                selected_index = max(0, selected_index - page_rows)
            elif key == ord("s"):
                severity_index = (severity_index + 1) % len(SEVERITY_VALUE)
                selected_index = offset = 0
            elif key == ord("c"):
                confidence = round((confidence + 0.1) % 1.1, 1)
                selected_index = offset = 0
            elif key == ord("o"):
                modes = ("severity", "location", "engine")
                sort_mode = modes[(modes.index(sort_mode) + 1) % len(modes)]
                selected_index = offset = 0
            elif key == ord("b"):
                show_suppressed = not show_suppressed
                selected_index = offset = 0
                message = "Baselined findings shown" if show_suppressed else "Baselined findings hidden"
            elif key == ord("/"):
                prompt_search()
            elif key == ord("r"):
                rescan()
            elif key == ord("e"):
                try:
                    export("json")
                except OSError as exc:
                    message = f"Export failed: {exc}"
            elif key == ord("E"):
                try:
                    export("sarif")
                except OSError as exc:
                    message = f"Export failed: {exc}"
            elif key == ord("?"):
                message = "PgUp/PgDn page · / empty clears search · e JSON · E SARIF · Esc/q exits"

    try:
        return curses.wrapper(dashboard)
    except KeyboardInterrupt:
        return 130
    except curses.error as exc:
        print(f"error: terminal is too small or incompatible: {exc}", file=sys.stderr)
        return 2


def run_gui() -> int:
    try:
        from app import App
    except Exception as exc:
        print(f"error: GUI dependencies are unavailable: {exc}", file=sys.stderr)
        print("Install requirements.txt, or use --tui/--cli.", file=sys.stderr)
        return 2
    try:
        App().mainloop()
        return 0
    except Exception as exc:
        print(f"error: GUI could not start: {exc}", file=sys.stderr)
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_engines:
        print("\n".join(f"{i:2}. {name:<15} {desc}" for i, (name, desc) in enumerate(ENGINE_DESCRIPTIONS.items(), 1)))
        return 0
    if args.list_ideas:
        print("Experimental Daybreak research track (not yet production detectors):")
        print("\n".join(f"{i:2}. {name}\n    {description}" for i, (name, description) in enumerate(EXPERIMENTAL_IDEAS, 1)))
        return 0
    if args.gui:
        return run_gui()
    if args.tui:
        return run_tui(args)
    return run_cli(args)


if __name__ == "__main__":
    raise SystemExit(main())
