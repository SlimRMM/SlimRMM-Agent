"""
Secure ZIP Handler Module.

Prevents ZIP-Slip attacks by validating archive member paths.
"""

import logging
import os
import zipfile
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ZipSecurityError(Exception):
    """Raised when a ZIP security violation is detected."""
    pass


def safe_extract_zip(
    zip_path: str,
    extract_to: str,
    max_file_size: int = 1024 * 1024 * 100,  # 100 MB per file
    max_total_size: int = 1024 * 1024 * 1024,  # 1 GB total
    max_files: int = 10000,
) -> Dict[str, Any]:
    """
    Safely extract a ZIP file, preventing ZIP-Slip attacks.

    This function validates each archive member to ensure:
    1. No path traversal (../) in member names
    2. No absolute paths
    3. All extracted files stay within the target directory
    4. File sizes are within limits
    5. Total extraction size is within limits
    6. Number of files is within limits

    Args:
        zip_path: Path to the ZIP file.
        extract_to: Directory to extract files to.
        max_file_size: Maximum size per file in bytes.
        max_total_size: Maximum total extraction size in bytes.
        max_files: Maximum number of files to extract.

    Returns:
        Dict with extraction results.

    Raises:
        ZipSecurityError: If a security violation is detected.
        FileNotFoundError: If the ZIP file doesn't exist.
        zipfile.BadZipFile: If the ZIP file is corrupted.

    Example:
        >>> safe_extract_zip("/tmp/archive.zip", "/tmp/extracted")
        {"success": True, "extracted_to": "/tmp/extracted", "file_count": 5}
    """
    # Validate inputs
    if not zip_path:
        raise ZipSecurityError("Empty zip path provided")

    if not extract_to:
        raise ZipSecurityError("Empty extraction path provided")

    # Check if ZIP file exists
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    if not os.path.isfile(zip_path):
        raise ZipSecurityError(f"Not a file: {zip_path}")

    # Resolve the extraction directory to absolute path
    extract_base = Path(extract_to).resolve()

    # Create extraction directory if it doesn't exist
    extract_base.mkdir(parents=True, exist_ok=True)

    extracted_files = []
    total_size = 0

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            members = zip_ref.namelist()

            # Check file count
            if len(members) > max_files:
                raise ZipSecurityError(
                    f"Too many files in archive: {len(members)} > {max_files}"
                )

            # First pass: validate all members before extracting any
            for member in members:
                # Skip empty names
                if not member:
                    continue

                # Check for absolute paths
                if member.startswith("/") or member.startswith("\\"):
                    raise ZipSecurityError(
                        f"Absolute path in archive: {member}"
                    )

                # Check for path traversal attempts
                if ".." in member:
                    raise ZipSecurityError(
                        f"Path traversal attempt in archive: {member}"
                    )

                # Check for backslash paths (Windows-style)
                if "\\" in member:
                    # Convert to forward slashes and check again
                    normalized = member.replace("\\", "/")
                    if ".." in normalized:
                        raise ZipSecurityError(
                            f"Path traversal attempt in archive: {member}"
                        )

                # Resolve the target path
                try:
                    target_path = (extract_base / member).resolve()
                except (OSError, ValueError) as e:
                    raise ZipSecurityError(
                        f"Invalid path in archive: {member} - {e}"
                    )

                # Ensure the target is within the extraction directory
                try:
                    target_path.relative_to(extract_base)
                except ValueError:
                    raise ZipSecurityError(
                        f"ZIP-Slip attempt detected: {member} would extract to {target_path}"
                    )

                # Check file size
                info = zip_ref.getinfo(member)
                if info.file_size > max_file_size:
                    raise ZipSecurityError(
                        f"File too large: {member} ({info.file_size} > {max_file_size} bytes)"
                    )

                total_size += info.file_size
                if total_size > max_total_size:
                    raise ZipSecurityError(
                        f"Total extraction size exceeds limit: {total_size} > {max_total_size} bytes"
                    )

            # Second pass: extract files
            for member in members:
                if not member:
                    continue

                # Skip directory entries (they end with /)
                if member.endswith("/"):
                    target_dir = (extract_base / member).resolve()
                    target_dir.mkdir(parents=True, exist_ok=True)
                    continue

                # Extract the file
                try:
                    # Create parent directories
                    target_path = (extract_base / member).resolve()
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    # Extract with controlled permissions
                    source = zip_ref.open(member)
                    with open(target_path, "wb") as target:
                        # Read in chunks to handle large files
                        chunk_size = 1024 * 1024  # 1 MB
                        while True:
                            chunk = source.read(chunk_size)
                            if not chunk:
                                break
                            target.write(chunk)
                    source.close()

                    # Set safe permissions (no execute)
                    os.chmod(target_path, 0o644)

                    extracted_files.append(str(target_path))
                    logger.debug(f"Extracted: {member}")

                except Exception as e:
                    logger.error(f"Failed to extract {member}: {e}")
                    raise ZipSecurityError(f"Extraction failed for {member}: {e}")

        logger.info(f"Successfully extracted {len(extracted_files)} files to {extract_base}")

        return {
            "success": True,
            "extracted_to": str(extract_base),
            "file_count": len(extracted_files),
            "total_size": total_size,
            "files": extracted_files,
        }

    except zipfile.BadZipFile as e:
        raise ZipSecurityError(f"Corrupted ZIP file: {e}")
    except Exception as e:
        if isinstance(e, ZipSecurityError):
            raise
        raise ZipSecurityError(f"Extraction failed: {e}")


def is_safe_zip(zip_path: str) -> bool:
    """
    Check if a ZIP file is safe to extract (no security issues).

    Args:
        zip_path: Path to the ZIP file.

    Returns:
        True if the ZIP is safe, False otherwise.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for member in zip_ref.namelist():
                if not member:
                    continue

                # Check for absolute paths
                if member.startswith("/") or member.startswith("\\"):
                    return False

                # Check for path traversal
                if ".." in member:
                    return False

        return True

    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return False
