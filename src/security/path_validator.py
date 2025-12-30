"""
Path Validation Module.

Prevents path traversal attacks by validating that requested paths
are within allowed directories.
"""

import os
from pathlib import Path
from typing import Optional, Set


class PathValidationError(Exception):
    """Raised when path validation fails."""
    pass


# Default allowed base paths for file operations
DEFAULT_ALLOWED_PATHS: Set[str] = {
    "/home",
    "/Users",
    "/tmp",
    "/var/log",
    "/var/tmp",
    "/opt",
}

# Paths that should NEVER be accessible
FORBIDDEN_PATHS: Set[str] = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "/var/lib/rmm",  # Agent installation directory
}


def validate_path(
    requested_path: str,
    allowed_bases: Optional[Set[str]] = None,
    check_exists: bool = False,
) -> Path:
    """
    Validate that a path is within allowed directories.

    This function prevents path traversal attacks by:
    1. Resolving the path to its absolute form (handles .., symlinks, etc.)
    2. Checking if the resolved path is under an allowed base directory
    3. Checking against forbidden paths

    Args:
        requested_path: The path requested by the user
        allowed_bases: Set of allowed base directories. Defaults to DEFAULT_ALLOWED_PATHS.
        check_exists: If True, also verify the path exists.

    Returns:
        The resolved Path object if validation passes.

    Raises:
        PathValidationError: If the path is not allowed or validation fails.

    Example:
        >>> validate_path("/home/user/documents")
        PosixPath('/home/user/documents')

        >>> validate_path("/etc/shadow")
        PathValidationError: Access to '/etc/shadow' is forbidden

        >>> validate_path("/home/user/../../../etc/passwd")
        PathValidationError: Path '/etc/passwd' is not in allowed directories
    """
    if allowed_bases is None:
        allowed_bases = DEFAULT_ALLOWED_PATHS

    # Handle empty or None path
    if not requested_path:
        raise PathValidationError("Empty path provided")

    try:
        # Resolve to absolute path (handles .., symlinks, etc.)
        # Using strict=False to allow paths that don't exist yet
        resolved = Path(requested_path).resolve()
    except (OSError, ValueError) as e:
        raise PathValidationError(f"Invalid path: {e}")

    resolved_str = str(resolved)

    # Check against forbidden paths first
    for forbidden in FORBIDDEN_PATHS:
        if resolved_str.startswith(forbidden) or resolved_str == forbidden:
            raise PathValidationError(f"Access to '{resolved_str}' is forbidden")

    # Check if path is under any allowed base
    is_allowed = False
    for base in allowed_bases:
        try:
            base_resolved = Path(base).resolve()
            # Check if resolved path is relative to base
            resolved.relative_to(base_resolved)
            is_allowed = True
            break
        except ValueError:
            continue

    if not is_allowed:
        raise PathValidationError(
            f"Path '{resolved_str}' is not in allowed directories: {allowed_bases}"
        )

    # Optionally check if path exists
    if check_exists and not resolved.exists():
        raise PathValidationError(f"Path does not exist: {resolved_str}")

    return resolved


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is safe (no path components).

    Args:
        filename: The filename to check.

    Returns:
        True if the filename is safe, False otherwise.
    """
    # Check for path separators
    if "/" in filename or "\\" in filename:
        return False

    # Check for path traversal attempts
    if ".." in filename:
        return False

    # Check for null bytes
    if "\x00" in filename:
        return False

    # Check for other dangerous characters
    dangerous_chars = {":", "*", "?", '"', "<", ">", "|"}
    if any(c in filename for c in dangerous_chars):
        return False

    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing dangerous characters.

    Args:
        filename: The filename to sanitize.

    Returns:
        A sanitized filename.
    """
    # Get just the basename (no directory components)
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Replace dangerous characters with underscores
    dangerous_chars = {"/", "\\", ":", "*", "?", '"', "<", ">", "|", ".."}
    for char in dangerous_chars:
        filename = filename.replace(char, "_")

    # Ensure filename is not empty
    if not filename or filename.strip() in (".", ".."):
        filename = "unnamed_file"

    return filename
