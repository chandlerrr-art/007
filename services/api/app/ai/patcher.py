"""Conservative, pluggable patch-candidate engine.

The built-in provider performs only narrow, reviewable source transformations.
Unknown patterns fail closed; a deployment may replace the provider with an
approved model adapter while keeping path checks, diff validation, and review
workflow in this module.
"""
import difflib
import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from app.models import DiscoveredVulnerability


class PatchGenerationError(ValueError):
    pass


@dataclass(frozen=True)
class PatchCandidate:
    target_file_path: str
    unified_diff: str
    confidence: float
    strategy: str
    rationale: str


class PatchInferenceProvider(Protocol):
    """Model adapter contract; providers return patched source, never raw diffs."""

    def propose(self, *, vulnerability_type: str, severity: str, cvss_score: float,
                remediation_advice: str, endpoint_parameter: str | None,
                target_file_path: str, source_code: str) -> tuple[str, float, str]: ...


_configured_provider: PatchInferenceProvider | None = None


def configure_patch_provider(provider: PatchInferenceProvider | None) -> None:
    """Install a trusted model adapter during application startup."""
    global _configured_provider
    _configured_provider = provider


def normalize_repo_path(path: str) -> str:
    path = (path or "").replace("\\", "/")
    candidate = PurePosixPath(path)
    if not path or str(candidate) == "." or candidate.is_absolute() or re.match(r"^[A-Za-z]:", path) or any(part in {"..", ""} for part in candidate.parts):
        raise PatchGenerationError("target_file_path must be a repository-relative path without traversal segments.")
    if "\x00" in path:
        raise PatchGenerationError("target_file_path contains an invalid character.")
    return str(candidate)


def _sql_parameterization(source: str, dialect: str, expected_parameter: str | None) -> tuple[str, str] | None:
    if dialect not in {"sqlite", "postgresql", "mysql"}:
        raise PatchGenerationError("SQL injection remediation requires db_dialect: sqlite, postgresql, or mysql.")
    placeholder = "?" if dialect == "sqlite" else "%s"
    pattern = re.compile(
        r"^(?P<indent>[ \t]*)(?P<prefix>(?:return\s+)?)(?P<call>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.execute)\(\s*f(?P<quote>['\"])(?P<before>[^'\"\n]*)\{(?P<parameter>[A-Za-z_]\w*)\}(?P<after>[^'\"\n]*)(?P=quote)\s*\)\s*$",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        return None
    match = matches[0]
    if expected_parameter and match.group("parameter") != expected_parameter:
        return None
    replacement = (f"{match.group('indent')}{match.group('prefix')}{match.group('call')}({match.group('quote')}"
                   f"{match.group('before')}{placeholder}{match.group('after')}{match.group('quote')}, "
                   f"({match.group('parameter')},))")
    return pattern.sub(lambda _: replacement, source, count=1), "parameterized SQL execution"


def _authorization_guard(source: str) -> tuple[str, str] | None:
    # The explicit marker makes ownership and principal expressions reviewable.
    pattern = re.compile(r"^(?P<indent>[ \t]*)# 007:AUTHZ owner=(?P<owner>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*) principal=(?P<principal>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*$", re.MULTILINE)
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        return None
    match = matches[0]
    indent, deeper = match.group("indent"), match.group("indent") + "    "
    replacement = f"{indent}if {match.group('owner')} != {match.group('principal')}:\n{deeper}raise PermissionError(\"Forbidden\")"
    return pattern.sub(lambda _: replacement, source, count=1), "object ownership authorization guard"


def _integer_validation(source: str) -> tuple[str, str] | None:
    pattern = re.compile(r"^(?P<indent>[ \t]*)# 007:VALIDATE_INT name=(?P<name>[A-Za-z_]\w*)\s*$", re.MULTILINE)
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        return None
    match = matches[0]
    indent, deeper = match.group("indent"), match.group("indent") + "    "
    name = match.group("name")
    replacement = (f"{indent}try:\n{deeper}{name} = int({name})\n{indent}except (TypeError, ValueError) as exc:\n"
                   f"{deeper}raise ValueError(\"{name} must be an integer\") from exc")
    return pattern.sub(lambda _: replacement, source, count=1), "strict integer input validation"


def _diff(path: str, before: str, after: str) -> str:
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    if before and not before.endswith(("\n", "\r")):
        before_lines[-1] += "\n"
    if after and not after.endswith(("\n", "\r")):
        after_lines[-1] += "\n"
    body = "".join(difflib.unified_diff(before_lines, after_lines, fromfile=f"a/{path}", tofile=f"b/{path}", n=3))
    if not body:
        raise PatchGenerationError("The source did not contain a supported vulnerable pattern or remediation marker.")
    digest = hashlib.sha1(after.encode("utf-8")).hexdigest()[:7]
    return f"diff --git a/{path} b/{path}\nindex 0000000..{digest} 100644\n{body}"


def generate_patch(vulnerability: DiscoveredVulnerability, target_file_path: str, source_code: str,
                   *, db_dialect: str | None = None, endpoint_parameter: str | None = None,
                   inference_provider: PatchInferenceProvider | None = None) -> PatchCandidate:
    """Generate one deterministic candidate; never modifies a repository file."""
    if len(source_code) > 200_000:
        raise PatchGenerationError("source_code exceeds the 200 KB limit.")
    path = normalize_repo_path(target_file_path)
    kind = (vulnerability.vuln_type or "").lower().replace("-", "_")
    provider = inference_provider or _configured_provider
    if provider is not None:
        try:
            updated, confidence, rationale = provider.propose(
                vulnerability_type=kind, severity=vulnerability.severity,
                cvss_score=float(vulnerability.cvss_score or 0),
                remediation_advice=vulnerability.remediation_advice or "",
                endpoint_parameter=endpoint_parameter, target_file_path=path, source_code=source_code)
        except Exception as exc:
            raise PatchGenerationError("Configured patch inference provider failed.") from exc
        if not isinstance(updated, str) or len(updated) > 200_000 or updated == source_code:
            raise PatchGenerationError("Patch inference provider returned no valid source change.")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError) as exc:
            raise PatchGenerationError("Patch inference provider returned an invalid confidence score.") from exc
        if not 0 <= confidence <= 1:
            raise PatchGenerationError("Patch inference confidence must be between 0 and 1.")
        if path.endswith(".py"):
            try:
                ast.parse(updated)
            except SyntaxError as exc:
                raise PatchGenerationError("Patch inference provider returned invalid Python syntax.") from exc
        return PatchCandidate(path, _diff(path, source_code, updated), confidence, "configured-model-provider", str(rationale)[:1000])
    generated = None
    confidence = 0.0
    rationale = ""
    if kind in {"sqli", "sql_injection"}:
        generated = _sql_parameterization(source_code, db_dialect or "", endpoint_parameter)
        if generated:
            confidence = 0.92
            rationale = "A single Python f-string passed to execute() was converted to parameter binding. Review the driver placeholder and query semantics."
            if vulnerability.remediation_advice:
                rationale += f" Finding guidance: {vulnerability.remediation_advice[:300]}"
    elif kind in {"bola_idor", "idor", "broken_object_level_authorization"}:
        generated = _authorization_guard(source_code)
        if generated:
            confidence, rationale = 0.84, "An explicit ownership marker was replaced with an object-owner check. Confirm the principal and owner fields match application policy."
    elif kind in {"input_validation", "integer_boundary_overflow"}:
        generated = _integer_validation(source_code)
        if generated:
            confidence, rationale = 0.86, "An explicit integer-validation marker was replaced with a checked conversion. Confirm validation occurs before use."
    if generated is None:
        raise PatchGenerationError("No safe automatic transformation matched. Add a supported 007 remediation marker or use a reviewed model provider.")
    updated, strategy = generated
    return PatchCandidate(path, _diff(path, source_code, updated), confidence, strategy, rationale)
