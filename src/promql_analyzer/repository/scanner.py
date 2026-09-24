"""Recursive discovery of Prometheus-related YAML/YML files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from promql_analyzer.repository.models import RepositoryScanConfig

_YAML_SUFFIXES = {".yaml", ".yml"}


@dataclass(frozen=True)
class DiscoveredFile:
    """A file discovered by ``RepositoryScanner``."""

    path: Path
    relative_path: str


class RepositoryScanner:
    """Discover YAML/YML files under a file, directory, or repository root."""

    def __init__(self, config: RepositoryScanConfig | None = None) -> None:
        self.config = config if config is not None else RepositoryScanConfig()

    def discover(self, root: Path | str) -> list[DiscoveredFile]:
        """Return matching YAML/YML files under ``root``.

        ``root`` may be:
        - a single ``.yaml`` / ``.yml`` file
        - a directory / repository root (searched recursively)
        """
        root_path = Path(root).resolve()
        if not root_path.exists():
            raise FileNotFoundError(f"path not found: {root_path}")

        if root_path.is_file():
            if root_path.suffix.lower() not in _YAML_SUFFIXES:
                raise ValueError(
                    f"expected a .yaml/.yml file or directory, got: {root_path}"
                )
            if not self._is_included(root_path.name) or self._is_excluded(
                root_path.name
            ):
                return []
            return [DiscoveredFile(path=root_path, relative_path=root_path.name)]

        discovered: list[DiscoveredFile] = []
        for path in sorted(root_path.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _YAML_SUFFIXES:
                continue
            try:
                relative = path.relative_to(root_path).as_posix()
            except ValueError:
                relative = str(path)
            if path.is_symlink() and not self.config.follow_symlinks:
                continue
            if self._is_excluded(relative):
                continue
            if not self._is_included(relative):
                continue
            discovered.append(DiscoveredFile(path=path, relative_path=relative))
        return discovered

    def _is_included(self, relative: str) -> bool:
        patterns = self.config.include_globs
        if not patterns:
            return True
        return any(_glob_match(relative, pattern) for pattern in patterns)

    def _is_excluded(self, relative: str) -> bool:
        return any(
            _glob_match(relative, pattern) for pattern in self.config.exclude_globs
        )


def _glob_match(path: str, pattern: str) -> bool:
    """Match a relative path against include/exclude globs (supports ``**``)."""
    normalized = path.replace("\\", "/").lstrip("./")
    pattern = pattern.replace("\\", "/").lstrip("./")
    posix = PurePosixPath(normalized)

    if posix.match(pattern):
        return True

    # ``**/*.yaml`` should also match root-level ``alerts.yaml``.
    name_pattern = pattern[3:] if pattern.startswith("**/") else pattern
    if "/" not in name_pattern and PurePosixPath(posix.name).match(name_pattern):
        return True

    # Directory excludes such as ``**/vendor/**`` or ``.venv/**``.
    if pattern.endswith("/**"):
        dir_pattern = pattern[:-3]
        core = dir_pattern[3:] if dir_pattern.startswith("**/") else dir_pattern
        if core and (
            core in posix.parts
            or normalized == core
            or normalized.startswith(f"{core}/")
        ):
            return True
        for index in range(len(posix.parts)):
            prefix = PurePosixPath(*posix.parts[: index + 1])
            if prefix.match(dir_pattern):
                return True

    return False
