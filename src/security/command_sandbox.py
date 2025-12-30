"""
Command Sandbox Module.

Provides safe command execution without shell=True.
Implements command whitelisting and argument validation.
"""

import logging
import shlex
import subprocess
from typing import Optional, Set

logger = logging.getLogger(__name__)


class CommandNotAllowedError(Exception):
    """Raised when a command is not in the whitelist."""
    pass


class CommandExecutionError(Exception):
    """Raised when command execution fails."""
    pass


# Whitelisted commands that are safe to execute
# These are the base commands (without path)
ALLOWED_COMMANDS: Set[str] = {
    # System information
    "uname",
    "hostname",
    "whoami",
    "id",
    "uptime",
    "date",
    "df",
    "free",
    "top",
    "ps",
    "lscpu",
    "lsblk",
    "lspci",
    "lsusb",

    # Network
    "ip",
    "ifconfig",
    "netstat",
    "ss",
    "ping",
    "traceroute",
    "dig",
    "nslookup",
    "curl",
    "wget",

    # File operations (read-only)
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "file",
    "stat",
    "du",
    "find",

    # Process management
    "kill",
    "pkill",

    # Package management (read operations)
    "apt",
    "apt-get",
    "dpkg",
    "rpm",
    "yum",
    "dnf",
    "pacman",
    "brew",

    # Service management
    "systemctl",
    "service",
    "launchctl",

    # macOS specific
    "sw_vers",
    "system_profiler",
    "softwareupdate",
    "pkgutil",
    "defaults",

    # Utilities
    "echo",
    "grep",
    "awk",
    "sed",
    "sort",
    "uniq",
    "cut",
    "tr",
    "xargs",
}

# Characters that should never appear in command arguments
DANGEROUS_CHARACTERS: Set[str] = {
    ";",      # Command separator
    "|",      # Pipe
    "&",      # Background/AND
    "$",      # Variable expansion
    "`",      # Command substitution
    "(",      # Subshell
    ")",
    "{",      # Brace expansion
    "}",
    "<",      # Redirection
    ">",
    "\n",     # Newline
    "\r",
    "\x00",   # Null byte
}


def validate_argument(arg: str) -> bool:
    """
    Validate a command argument for dangerous characters.

    Args:
        arg: The argument to validate.

    Returns:
        True if the argument is safe, False otherwise.
    """
    for char in DANGEROUS_CHARACTERS:
        if char in arg:
            return False
    return True


def execute_safe_command(
    command: str,
    allowed_commands: Optional[Set[str]] = None,
    timeout: int = 30,
    cwd: Optional[str] = None,
) -> str:
    """
    Execute a command safely without shell=True.

    This function:
    1. Parses the command using shlex (handles quotes properly)
    2. Validates the base command against a whitelist
    3. Validates all arguments for dangerous characters
    4. Executes without shell=True to prevent injection

    Args:
        command: The command string to execute.
        allowed_commands: Set of allowed base commands. Defaults to ALLOWED_COMMANDS.
        timeout: Maximum execution time in seconds.
        cwd: Working directory for the command.

    Returns:
        The command output as a string.

    Raises:
        CommandNotAllowedError: If the command is not whitelisted.
        CommandExecutionError: If the command fails.

    Example:
        >>> execute_safe_command("ls -la /home")
        "total 0..."

        >>> execute_safe_command("rm -rf /")
        CommandNotAllowedError: Command 'rm' is not allowed

        >>> execute_safe_command("ls; cat /etc/passwd")
        CommandNotAllowedError: Argument contains dangerous characters: ';'
    """
    if allowed_commands is None:
        allowed_commands = ALLOWED_COMMANDS

    # Handle empty command
    if not command or not command.strip():
        raise CommandNotAllowedError("Empty command provided")

    try:
        # Parse command using shlex (handles quotes properly)
        parts = shlex.split(command)
    except ValueError as e:
        raise CommandNotAllowedError(f"Invalid command syntax: {e}")

    if not parts:
        raise CommandNotAllowedError("Empty command after parsing")

    # Get the base command (without path)
    base_command = parts[0].split("/")[-1]

    # Check if command is whitelisted
    if base_command not in allowed_commands:
        logger.warning(f"Blocked command not in whitelist: {base_command}")
        raise CommandNotAllowedError(f"Command '{base_command}' is not allowed")

    # Validate all arguments for dangerous characters
    for arg in parts[1:]:
        if not validate_argument(arg):
            for char in DANGEROUS_CHARACTERS:
                if char in arg:
                    logger.warning(f"Blocked argument with dangerous character: {char}")
                    raise CommandNotAllowedError(
                        f"Argument contains dangerous character: '{char}'"
                    )

    try:
        # Execute without shell=True
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            # Don't inherit parent environment completely
            env={"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or f"Command exited with code {result.returncode}"
            logger.error(f"Command failed: {error_msg}")
            raise CommandExecutionError(error_msg)

        return result.stdout.strip()

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {command}")
        raise CommandExecutionError(f"Command timed out after {timeout} seconds")
    except FileNotFoundError:
        logger.error(f"Command not found: {base_command}")
        raise CommandExecutionError(f"Command not found: {base_command}")
    except PermissionError:
        logger.error(f"Permission denied executing: {base_command}")
        raise CommandExecutionError(f"Permission denied: {base_command}")
    except Exception as e:
        logger.error(f"Unexpected error executing command: {e}")
        raise CommandExecutionError(f"Execution failed: {e}")


def get_allowed_commands() -> Set[str]:
    """Return the set of allowed commands."""
    return ALLOWED_COMMANDS.copy()


def add_allowed_command(command: str) -> None:
    """
    Add a command to the whitelist.

    Args:
        command: The command to add.
    """
    ALLOWED_COMMANDS.add(command)


def remove_allowed_command(command: str) -> None:
    """
    Remove a command from the whitelist.

    Args:
        command: The command to remove.
    """
    ALLOWED_COMMANDS.discard(command)
