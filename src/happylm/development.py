"""A2 reference Git-development workflow with immutable review evidence.

The module deliberately supports a narrow, local Git flow.  A trusted server
registers repositories and protected checks; model supplied requests can only
refer to their exact identifiers and digests.  Edits are content-addressed,
the candidate commit is immutable, and protected checks run in child
processes before the durable ledger may mark the action verified.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from .integrity import canonical_json, is_sha256_digest, sha256_json
from .policy import ActionRequest


_GIT_COMMIT = re.compile(r"[0-9a-f]{40,64}")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_MAX_EDIT_BYTES = 1_048_576
_MAX_CHECK_OUTPUT_BYTES = 262_144
PROTECTED_CHECK_ENVIRONMENT_DIGEST = sha256_json(
    {
        "id": "happy.protected-check-environment",
        "version": "1",
        "shell": False,
        "stdin": "devnull",
        "environment": {
            "locale": "C.UTF-8",
            "python_hash_seed": "0",
            "python_no_user_site": True,
            "python_no_bytecode": True,
        },
        "postconditions": ["candidate_head_unchanged", "workspace_clean"],
    }
)


class DevelopmentError(RuntimeError):
    """Machine-readable development-workflow failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC).isoformat()


def _relative_path(value: str, *, allow_dot: bool = False) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("path must not be absolute or contain parent traversal")
    normalized = str(path)
    if normalized == "." and not allow_dot:
        raise ValueError("path must name a file")
    if path.parts and path.parts[0] == ".git":
        raise ValueError("Git administrative paths are never editable")
    return normalized


def _safe_id(value: str, name: str) -> str:
    if not _SAFE_ID.fullmatch(value):
        raise ValueError(f"{name} contains unsupported characters")
    return value


def _git_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
    }
    if extra:
        env.update(extra)
    return env


class ContributionKind(StrEnum):
    AI = "ai"
    HUMAN = "human"


@dataclass(frozen=True, slots=True)
class RepositoryRegistration:
    repository_uri: str
    local_path: str

    def __post_init__(self) -> None:
        if not self.repository_uri.startswith("repo://"):
            raise ValueError("repository URI must use repo://")
        ActionRequest(
            "repository.registration",
            "repository-registry",
            "register",
            self.repository_uri,
            {},
        )
        path = Path(self.local_path)
        if not path.is_absolute():
            raise ValueError("registered repository path must be absolute")

    def to_dict(self) -> dict[str, str]:
        return {
            "repository_uri": self.repository_uri,
            "local_path": self.local_path,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


class RepositoryRegistry:
    """Trusted, in-memory repository mapping for the A2 reference slice."""

    def __init__(self, registrations: Iterable[RepositoryRegistration] = ()) -> None:
        self._items: dict[str, RepositoryRegistration] = {}
        for registration in registrations:
            self.register(registration)

    def register(self, registration: RepositoryRegistration) -> None:
        if registration.repository_uri in self._items:
            raise DevelopmentError("repository_exists", "repository URI is already registered")
        resolved = Path(registration.local_path).resolve(strict=True)
        if not resolved.is_dir():
            raise DevelopmentError("repository_invalid", "registered repository is not a directory")
        self._items[registration.repository_uri] = RepositoryRegistration(
            registration.repository_uri, str(resolved)
        )

    def resolve(
        self,
        repository_uri: str,
        registration_digest: str | None = None,
    ) -> RepositoryRegistration:
        try:
            registration = self._items[repository_uri]
        except KeyError as error:
            raise DevelopmentError(
                "repository_not_registered", "repository URI is not registered"
            ) from error
        if registration_digest is not None:
            if not is_sha256_digest(registration_digest):
                raise ValueError("repository registration reference must be SHA-256")
            if registration.digest != registration_digest:
                raise DevelopmentError(
                    "repository_registration_mismatch",
                    "repository registration digest does not match",
                )
        return registration


@dataclass(frozen=True, slots=True)
class ProtectedCheckDefinition:
    check_id: str
    version: str
    argv: tuple[str, ...]
    timeout_seconds: float
    working_directory: str = "."
    implementation_files: tuple[tuple[str, str], ...] = ()
    sandbox_profile_digest: str | None = None

    def __post_init__(self) -> None:
        _safe_id(self.check_id, "check id")
        _safe_id(self.version, "check version")
        if not self.argv or any(not item or "\x00" in item for item in self.argv):
            raise ValueError("protected check requires non-empty argv")
        if not (0 < self.timeout_seconds <= 900):
            raise ValueError("protected check timeout must be in (0, 900]")
        _relative_path(self.working_directory, allow_dot=True)
        seen_paths: set[str] = set()
        for path_value, digest in self.implementation_files:
            path = Path(path_value)
            if not path.is_absolute() or path_value in seen_paths:
                raise ValueError("protected implementation paths must be absolute and unique")
            if not is_sha256_digest(digest):
                raise ValueError("protected implementation digest must be SHA-256")
            seen_paths.add(path_value)
        if self.sandbox_profile_digest is not None and not is_sha256_digest(
            self.sandbox_profile_digest
        ):
            raise ValueError("sandbox profile reference must be SHA-256")
        if self.sandbox_profile_digest is not None:
            executable = Path(self.argv[0])
            if not executable.is_absolute() or self.argv[0] not in seen_paths:
                raise ValueError(
                    "sandboxed check executable must be an absolute protected implementation"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "version": self.version,
            "argv": list(self.argv),
            "timeout_seconds": float(self.timeout_seconds),
            "working_directory": self.working_directory,
            "implementation_files": [
                {"path": path, "digest": digest}
                for path, digest in self.implementation_files
            ],
            "environment_digest": PROTECTED_CHECK_ENVIRONMENT_DIGEST,
            "sandbox_profile_digest": self.sandbox_profile_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


class ProtectedCheckRegistry:
    def __init__(self, definitions: Iterable[ProtectedCheckDefinition] = ()) -> None:
        self._items: dict[str, ProtectedCheckDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ProtectedCheckDefinition) -> None:
        if definition.digest in self._items:
            raise DevelopmentError("check_exists", "protected check is already registered")
        self._items[definition.digest] = definition

    def resolve(self, digest: str) -> ProtectedCheckDefinition:
        if not is_sha256_digest(digest):
            raise ValueError("protected check reference must be SHA-256")
        try:
            return self._items[digest]
        except KeyError as error:
            raise DevelopmentError(
                "check_not_registered", "protected check digest is not registered"
            ) from error


class ContentAddressedArtifactStore:
    """Immutable local artifact store addressed by SHA-256."""

    def __init__(self, root: str | Path) -> None:
        unresolved = Path(root)
        if unresolved.exists() and unresolved.is_symlink():
            raise ValueError("artifact root must not be a symlink")
        unresolved.mkdir(parents=True, exist_ok=True)
        self.root = unresolved.resolve(strict=True)

    def _path(self, digest: str) -> Path:
        if not is_sha256_digest(digest):
            raise ValueError("artifact reference must be SHA-256")
        return self.root / digest[:2] / digest[2:]

    def put_bytes(self, value: bytes) -> str:
        digest = _sha256_bytes(value)
        path = self._path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            if self.get_bytes(digest) != value:
                raise DevelopmentError("artifact_collision", "artifact digest collision")
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        return digest

    def get_bytes(self, digest: str, *, max_bytes: int | None = None) -> bytes:
        path = self._path(digest)
        if path.is_symlink() or not path.is_file():
            raise DevelopmentError("artifact_missing", "artifact was not found")
        value = path.read_bytes()
        if max_bytes is not None and len(value) > max_bytes:
            raise DevelopmentError("artifact_too_large", "artifact exceeds allowed size")
        if _sha256_bytes(value) != digest:
            raise DevelopmentError("artifact_corrupt", "artifact digest does not match content")
        return value

    def put_json(self, value: Mapping[str, Any]) -> str:
        return self.put_bytes(canonical_json(dict(value)).encode("utf-8"))

    def get_json(self, digest: str) -> dict[str, Any]:
        value = json.loads(self.get_bytes(digest).decode("utf-8"))
        if not isinstance(value, dict):
            raise DevelopmentError("artifact_invalid", "JSON artifact must be an object")
        return value


@dataclass(frozen=True, slots=True)
class EditInstruction:
    relative_path: str
    expected_before_digest: str
    replacement_artifact_digest: str
    contributor_kind: ContributionKind
    contributor_principal: str

    def __post_init__(self) -> None:
        _relative_path(self.relative_path)
        if not is_sha256_digest(self.expected_before_digest) or not is_sha256_digest(
            self.replacement_artifact_digest
        ):
            raise ValueError("edit instruction requires SHA-256 commitments")
        if not self.contributor_principal.strip():
            raise ValueError("contributor principal must not be empty")

    def to_dict(self) -> dict[str, str]:
        return {
            "relative_path": self.relative_path,
            "expected_before_digest": self.expected_before_digest,
            "replacement_artifact_digest": self.replacement_artifact_digest,
            "contributor_kind": self.contributor_kind.value,
            "contributor_principal": self.contributor_principal,
        }


@dataclass(frozen=True, slots=True)
class ContributionRecord:
    sequence: int
    relative_path: str
    before_digest: str
    after_digest: str
    change_digest: str
    contributor_kind: ContributionKind
    contributor_principal: str
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "relative_path": self.relative_path,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "change_digest": self.change_digest,
            "contributor_kind": self.contributor_kind.value,
            "contributor_principal": self.contributor_principal,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True, slots=True)
class ProtectedCheckReceipt:
    check_id: str
    check_version: str
    definition_digest: str
    environment_digest: str
    candidate_commit: str
    exit_code: int | None
    passed: bool
    failure_reason: str | None
    stdout_artifact_digest: str
    stderr_artifact_digest: str
    started_at: str
    finished_at: str
    sandbox_profile_digest: str | None = None
    sandbox_details: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_version": self.check_version,
            "definition_digest": self.definition_digest,
            "environment_digest": self.environment_digest,
            "candidate_commit": self.candidate_commit,
            "exit_code": self.exit_code,
            "passed": self.passed,
            "failure_reason": self.failure_reason,
            "stdout_artifact_digest": self.stdout_artifact_digest,
            "stderr_artifact_digest": self.stderr_artifact_digest,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "sandbox_profile_digest": self.sandbox_profile_digest,
            "sandbox_details": (
                None if self.sandbox_details is None else dict(self.sandbox_details)
            ),
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class DevelopmentReview:
    work_id: str
    operation_id: str
    action_id: str
    repository_uri: str
    repository_registration_digest: str
    base_commit: str
    candidate_commit: str
    branch_name: str
    diff_artifact_digest: str
    diff_digest: str
    contributions: tuple[ContributionRecord, ...]
    checks: tuple[ProtectedCheckReceipt, ...]
    unresolved_items: tuple[str, ...]
    created_at: str

    @property
    def verified(self) -> bool:
        return bool(self.checks) and all(item.passed for item in self.checks) and not (
            self.unresolved_items
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "happy-development-review/v1",
            "work_id": self.work_id,
            "operation_id": self.operation_id,
            "action_id": self.action_id,
            "repository_uri": self.repository_uri,
            "repository_registration_digest": self.repository_registration_digest,
            "base_commit": self.base_commit,
            "candidate_commit": self.candidate_commit,
            "branch_name": self.branch_name,
            "diff_artifact_digest": self.diff_artifact_digest,
            "diff_digest": self.diff_digest,
            "contributions": [item.to_dict() for item in self.contributions],
            "checks": [item.to_dict() for item in self.checks],
            "unresolved_items": list(self.unresolved_items),
            "verified": self.verified,
            "created_at": self.created_at,
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


class GitDevelopmentWorkspace:
    """One isolated clone pinned to an exact base commit."""

    def __init__(
        self,
        *,
        root: Path,
        repository: RepositoryRegistration,
        base_commit: str,
        branch_name: str,
        clock: Callable[[], datetime],
    ) -> None:
        self.root = root
        self.repository = repository
        self.base_commit = base_commit
        self.branch_name = branch_name
        self._clock = clock
        self._contributions: list[ContributionRecord] = []
        self._candidate_commit: str | None = None

    @classmethod
    def create(
        cls,
        *,
        repository: RepositoryRegistration,
        base_commit: str,
        workspace_root: str | Path,
        workspace_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> "GitDevelopmentWorkspace":
        if not _GIT_COMMIT.fullmatch(base_commit):
            raise ValueError("base commit must be a full lowercase Git object id")
        _safe_id(workspace_id, "workspace id")
        source = Path(repository.local_path).resolve(strict=True)
        unresolved_root = Path(workspace_root)
        if unresolved_root.exists() and unresolved_root.is_symlink():
            raise DevelopmentError("workspace_root_invalid", "workspace root is a symlink")
        unresolved_root.mkdir(parents=True, exist_ok=True)
        root_parent = unresolved_root.resolve(strict=True)
        root = root_parent / workspace_id
        if root.exists() or root.is_symlink():
            raise DevelopmentError("workspace_exists", "workspace already exists")

        status = cls._run(source, ("git", "status", "--porcelain"))
        if status.stdout:
            raise DevelopmentError("source_dirty", "source repository must be clean")
        resolved_base = cls._run(
            source, ("git", "rev-parse", "--verify", f"{base_commit}^{{commit}}")
        ).stdout.decode("utf-8").strip()
        if resolved_base != base_commit:
            raise DevelopmentError("base_commit_mismatch", "base commit is not exact")

        cls._run(
            root_parent,
            ("git", "clone", "--no-local", "--quiet", str(source), str(root)),
        )
        cls._run(root, ("git", "checkout", "--quiet", "--detach", base_commit))
        branch_name = f"happy/{workspace_id}"
        cls._run(root, ("git", "switch", "--quiet", "-c", branch_name))
        return cls(
            root=root,
            repository=repository,
            base_commit=base_commit,
            branch_name=branch_name,
            clock=clock or (lambda: datetime.now(UTC)),
        )

    @classmethod
    def reopen_candidate(
        cls,
        *,
        repository: RepositoryRegistration,
        base_commit: str,
        workspace_root: Path,
        workspace_id: str,
        candidate_commit: str,
        diff_digest: str,
    ) -> "GitDevelopmentWorkspace":
        """Open the recorded candidate for checks without cloning, editing or committing."""
        _safe_id(workspace_id, "workspace id")
        if not all(_GIT_COMMIT.fullmatch(commit) for commit in (base_commit, candidate_commit)):
            raise DevelopmentError("candidate_invalid", "handoff requires exact Git commits")
        root = workspace_root / workspace_id
        git_dir = root / ".git"
        if workspace_root.is_symlink() or root.is_symlink() or git_dir.is_symlink() or not git_dir.is_dir():
            raise DevelopmentError("candidate_workspace_invalid", "candidate workspace is missing or unsafe")
        history = cls._run(root, ("git", "rev-list", "--parents", "-1", "HEAD")).stdout.decode().split()
        if history != [candidate_commit, base_commit] or cls._run(
            root, ("git", "status", "--porcelain")
        ).stdout:
            raise DevelopmentError("candidate_changed", "candidate HEAD, parent or worktree changed")
        diff = cls._run(root, ("git", "diff", "--binary", base_commit, candidate_commit)).stdout
        if _sha256_bytes(diff) != diff_digest:
            raise DevelopmentError("candidate_changed", "candidate diff differs from the checkpoint")
        workspace = cls(
            root=root,
            repository=repository,
            base_commit=base_commit,
            branch_name=f"happy/{workspace_id}",
            clock=lambda: datetime.now(UTC),
        )
        workspace._candidate_commit = candidate_commit
        return workspace

    @staticmethod
    def _run(
        cwd: Path,
        argv: tuple[str, ...],
        *,
        timeout: float = 60,
        extra_env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                argv,
                cwd=cwd,
                env=_git_environment(extra_env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as error:
            raise DevelopmentError("git_timeout", f"Git command timed out: {argv[1]}") from error
        except subprocess.CalledProcessError as error:
            detail = error.stderr.decode("utf-8", errors="replace")[-1000:]
            raise DevelopmentError("git_failed", f"Git command failed: {detail}") from error

    def _editable_file(self, relative_path: str) -> Path:
        normalized = _relative_path(relative_path)
        path = self.root.joinpath(*PurePosixPath(normalized).parts)
        cursor = self.root
        for part in PurePosixPath(normalized).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise DevelopmentError("edit_target_invalid", "edit path contains a symlink")
        if path.is_symlink() or not path.is_file():
            raise DevelopmentError("edit_target_invalid", "edit target must be a regular file")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(self.root.resolve(strict=True))
        except ValueError as error:
            raise DevelopmentError("edit_scope_escape", "edit target leaves workspace") from error
        return path

    def apply_edit(
        self,
        instruction: EditInstruction,
        replacement: bytes,
    ) -> ContributionRecord:
        if self._candidate_commit is not None:
            raise DevelopmentError("candidate_frozen", "candidate commit is already frozen")
        if len(replacement) > _MAX_EDIT_BYTES:
            raise DevelopmentError("edit_too_large", "replacement exceeds A2 size limit")
        path = self._editable_file(instruction.relative_path)
        before = path.read_bytes()
        if _sha256_bytes(before) != instruction.expected_before_digest:
            raise DevelopmentError("stale_edit", "file no longer matches expected digest")
        if _sha256_bytes(replacement) != instruction.replacement_artifact_digest:
            raise DevelopmentError("replacement_mismatch", "replacement artifact digest mismatch")

        flags = os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(replacement)
            stream.flush()
            os.fsync(stream.fileno())
        after = path.read_bytes()
        before_digest = _sha256_bytes(before)
        after_digest = _sha256_bytes(after)
        record = ContributionRecord(
            sequence=len(self._contributions) + 1,
            relative_path=instruction.relative_path,
            before_digest=before_digest,
            after_digest=after_digest,
            change_digest=sha256_json(
                {
                    "relative_path": instruction.relative_path,
                    "before_digest": before_digest,
                    "after_digest": after_digest,
                }
            ),
            contributor_kind=instruction.contributor_kind,
            contributor_principal=instruction.contributor_principal,
            recorded_at=_utc_text(self._clock()),
        )
        self._contributions.append(record)
        return record

    def freeze_candidate(self, commit_message: str) -> tuple[str, bytes]:
        if self._candidate_commit is not None:
            raise DevelopmentError("candidate_frozen", "candidate commit is already frozen")
        if not commit_message.strip() or "\x00" in commit_message:
            raise ValueError("commit message must not be empty")
        changed = {
            item.decode("utf-8")
            for item in self._run(
                self.root, ("git", "diff", "--name-only", "-z")
            ).stdout.split(b"\x00")
            if item
        }
        staged = {
            item.decode("utf-8")
            for item in self._run(
                self.root, ("git", "diff", "--cached", "--name-only", "-z")
            ).stdout.split(b"\x00")
            if item
        }
        changed |= staged
        untracked = {
            item.decode("utf-8")
            for item in self._run(
                self.root, ("git", "ls-files", "--others", "--exclude-standard", "-z")
            ).stdout.split(b"\x00")
            if item
        }
        expected = {item.relative_path for item in self._contributions}
        if not expected or changed != expected or untracked:
            raise DevelopmentError(
                "unattributed_change", "every changed file must have contribution provenance"
            )
        latest: dict[str, str] = {}
        for contribution in self._contributions:
            latest[contribution.relative_path] = contribution.after_digest
        for relative_path, expected_digest in latest.items():
            if _sha256_bytes(self._editable_file(relative_path).read_bytes()) != expected_digest:
                raise DevelopmentError(
                    "unattributed_change",
                    "final file content differs from its last contribution",
                )
        self._run(self.root, ("git", "add", "--", *sorted(expected)))
        self._run(
            self.root,
            (
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--quiet",
                "-m",
                commit_message,
            ),
            extra_env={
                "GIT_AUTHOR_NAME": "Happy Proof Kernel",
                "GIT_AUTHOR_EMAIL": "proof-kernel.invalid",
                "GIT_COMMITTER_NAME": "Happy Proof Kernel",
                "GIT_COMMITTER_EMAIL": "proof-kernel.invalid",
            },
        )
        candidate = self._run(self.root, ("git", "rev-parse", "HEAD")).stdout.decode().strip()
        count = self._run(
            self.root, ("git", "rev-list", "--count", f"{self.base_commit}..{candidate}")
        ).stdout.decode().strip()
        if count != "1":
            raise DevelopmentError("candidate_history_invalid", "candidate must be one commit")
        if self._run(self.root, ("git", "status", "--porcelain")).stdout:
            raise DevelopmentError("candidate_dirty", "candidate workspace must be clean")
        diff = self._run(
            self.root, ("git", "diff", "--binary", self.base_commit, candidate)
        ).stdout
        self._candidate_commit = candidate
        return candidate, diff

    def run_protected_checks(
        self,
        definitions: tuple[ProtectedCheckDefinition, ...],
        artifacts: ContentAddressedArtifactStore,
        *,
        sandbox_profiles: Any | None = None,
        sandbox_runner: Any | None = None,
    ) -> tuple[ProtectedCheckReceipt, ...]:
        if self._candidate_commit is None:
            raise DevelopmentError("candidate_missing", "candidate must be frozen first")
        if not definitions:
            raise DevelopmentError("checks_missing", "at least one protected check is required")
        receipts: list[ProtectedCheckReceipt] = []
        for definition in definitions:
            started = datetime.now(UTC)
            cursor = self.root
            for part in PurePosixPath(definition.working_directory).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise DevelopmentError("check_cwd_invalid", "protected check cwd is invalid")
            cwd = cursor
            try:
                cwd.resolve(strict=True).relative_to(self.root.resolve(strict=True))
            except (FileNotFoundError, ValueError) as error:
                raise DevelopmentError(
                    "check_cwd_invalid", "protected check cwd is invalid"
                ) from error
            if not cwd.is_dir():
                raise DevelopmentError("check_cwd_invalid", "protected check cwd is invalid")
            failure: str | None = None
            exit_code: int | None = None
            for path_value, expected_digest in definition.implementation_files:
                path = Path(path_value)
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or _sha256_bytes(path.read_bytes()) != expected_digest
                ):
                    failure = "check_implementation_changed"
                    break
            sandbox_details: Mapping[str, Any] | None = None
            sandbox_profile_digest = definition.sandbox_profile_digest
            if failure is None and sandbox_profile_digest is not None:
                if sandbox_profiles is None or sandbox_runner is None:
                    failure = "sandbox_not_configured"
                    stdout = b""
                    stderr = b""
                else:
                    try:
                        profile = sandbox_profiles.resolve(sandbox_profile_digest)
                        sandboxed = sandbox_runner.run(
                            profile=profile,
                            repository=self.root,
                            candidate_commit=self._candidate_commit,
                            argv=definition.argv,
                            working_directory=definition.working_directory,
                            timeout_seconds=definition.timeout_seconds,
                        )
                        stdout = sandboxed.stdout
                        stderr = sandboxed.stderr
                        exit_code = sandboxed.exit_code
                        failure = sandboxed.failure_reason
                        sandbox_details = sandboxed.details
                    except Exception as error:
                        failure = getattr(error, "code", "sandbox_launch_failed")
                        stdout = b""
                        stderr = b""
            else:
                stdout = b""
                stderr = b""

            if sandbox_profile_digest is None:
                with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                    if failure is None:
                        try:
                            completed = subprocess.run(
                                definition.argv,
                                cwd=cwd,
                                env={
                                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                    "LC_ALL": "C.UTF-8",
                                    "LANG": "C.UTF-8",
                                    "PYTHONHASHSEED": "0",
                                    "PYTHONDONTWRITEBYTECODE": "1",
                                    "PYTHONNOUSERSITE": "1",
                                },
                                stdin=subprocess.DEVNULL,
                                stdout=stdout_file,
                                stderr=stderr_file,
                                timeout=definition.timeout_seconds,
                                check=False,
                            )
                            exit_code = completed.returncode
                        except subprocess.TimeoutExpired:
                            failure = "timeout"
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read(_MAX_CHECK_OUTPUT_BYTES + 1)
                    stderr = stderr_file.read(_MAX_CHECK_OUTPUT_BYTES + 1)
            if len(stdout) > _MAX_CHECK_OUTPUT_BYTES or len(stderr) > _MAX_CHECK_OUTPUT_BYTES:
                failure = "output_limit_exceeded"
                stdout = stdout[:_MAX_CHECK_OUTPUT_BYTES]
                stderr = stderr[:_MAX_CHECK_OUTPUT_BYTES]
            current = self._run(self.root, ("git", "rev-parse", "HEAD")).stdout.decode().strip()
            dirty = bool(self._run(self.root, ("git", "status", "--porcelain")).stdout)
            if current != self._candidate_commit:
                failure = "candidate_commit_changed"
            elif dirty:
                failure = "workspace_changed_by_check"
            passed = exit_code == 0 and failure is None
            receipt = ProtectedCheckReceipt(
                check_id=definition.check_id,
                check_version=definition.version,
                definition_digest=definition.digest,
                environment_digest=PROTECTED_CHECK_ENVIRONMENT_DIGEST,
                candidate_commit=self._candidate_commit,
                exit_code=exit_code,
                passed=passed,
                failure_reason=failure if failure else (None if passed else "nonzero_exit"),
                stdout_artifact_digest=artifacts.put_bytes(stdout),
                stderr_artifact_digest=artifacts.put_bytes(stderr),
                started_at=_utc_text(started),
                finished_at=_utc_text(datetime.now(UTC)),
                sandbox_profile_digest=sandbox_profile_digest,
                sandbox_details=sandbox_details,
            )
            receipts.append(receipt)
        return tuple(receipts)

    @property
    def contributions(self) -> tuple[ContributionRecord, ...]:
        return tuple(self._contributions)


def build_development_review(
    *,
    work_id: str,
    operation_id: str,
    action_id: str,
    workspace: GitDevelopmentWorkspace,
    candidate_commit: str,
    diff: bytes,
    checks: tuple[ProtectedCheckReceipt, ...],
    artifacts: ContentAddressedArtifactStore,
    unresolved_items: tuple[str, ...] = (),
    clock: Callable[[], datetime] | None = None,
) -> tuple[DevelopmentReview, str]:
    diff_artifact_digest = artifacts.put_bytes(diff)
    review = DevelopmentReview(
        work_id=work_id,
        operation_id=operation_id,
        action_id=action_id,
        repository_uri=workspace.repository.repository_uri,
        repository_registration_digest=workspace.repository.digest,
        base_commit=workspace.base_commit,
        candidate_commit=candidate_commit,
        branch_name=workspace.branch_name,
        diff_artifact_digest=diff_artifact_digest,
        diff_digest=_sha256_bytes(diff),
        contributions=workspace.contributions,
        checks=checks,
        unresolved_items=unresolved_items,
        created_at=_utc_text((clock or (lambda: datetime.now(UTC)))()),
    )
    return review, artifacts.put_json(review.to_dict())


GIT_DEVELOPMENT_ADAPTER_DIGEST = sha256_json(
    {
        "id": "happy.git-development",
        "version": "a2-reference/v1",
        "operations": ["prepare_reviewable_change"],
        "guarantees": [
            "exact_base_commit",
            "content_addressed_edits",
            "attributed_diff",
            "protected_check_receipts",
            "immutable_review_artifact",
        ],
    }
)
