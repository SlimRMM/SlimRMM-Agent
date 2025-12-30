"""Security modules for RMM Agent."""

from src.security.path_validator import validate_path, PathValidationError
from src.security.command_sandbox import execute_safe_command, CommandNotAllowedError
from src.security.zip_handler import safe_extract_zip, ZipSecurityError
from src.security.mtls import (
    create_ssl_context,
    get_websocket_ssl_options,
    save_certificate_files,
    load_certificate_files,
    certificates_exist,
    is_mtls_configured,
    setup_agent_mtls,
    MTLSError,
)

__all__ = [
    "validate_path",
    "PathValidationError",
    "execute_safe_command",
    "CommandNotAllowedError",
    "safe_extract_zip",
    "ZipSecurityError",
    "create_ssl_context",
    "get_websocket_ssl_options",
    "save_certificate_files",
    "load_certificate_files",
    "certificates_exist",
    "is_mtls_configured",
    "setup_agent_mtls",
    "MTLSError",
]
