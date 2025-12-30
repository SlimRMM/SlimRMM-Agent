"""
mTLS (Mutual TLS) Module for RMM Agent.

Provides secure WebSocket connections using client certificates.
"""

import json
import logging
import os
import ssl
from pathlib import Path
from typing import Optional, Dict, Any
import hashlib
import platform

logger = logging.getLogger(__name__)

# Default paths for certificate files
DEFAULT_CERT_DIR = Path.home() / ".rmm-agent" / "certs"
DEFAULT_CERT_PATH = DEFAULT_CERT_DIR / "agent.crt"
DEFAULT_KEY_PATH = DEFAULT_CERT_DIR / "agent.key"
DEFAULT_CA_PATH = DEFAULT_CERT_DIR / "ca.crt"
DEFAULT_CONFIG_PATH = Path.home() / ".rmm-agent" / "config.json"


class MTLSError(Exception):
    """Exception raised for mTLS-related errors."""
    pass


def get_machine_fingerprint() -> str:
    """
    Generate a unique fingerprint for this machine.

    Used to bind certificates to specific machines.

    Returns:
        A hexadecimal fingerprint string.
    """
    # Combine multiple system identifiers
    identifiers = [
        platform.node(),           # Hostname
        platform.machine(),        # CPU architecture
        platform.processor(),      # Processor info
    ]

    # Try to add MAC address
    try:
        import uuid
        mac = uuid.getnode()
        identifiers.append(str(mac))
    except Exception:
        pass

    combined = "|".join(identifiers)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


def ensure_cert_directory() -> Path:
    """
    Ensure the certificate directory exists with proper permissions.

    Returns:
        Path to the certificate directory.
    """
    cert_dir = DEFAULT_CERT_DIR
    cert_dir.mkdir(parents=True, exist_ok=True)

    # Set restrictive permissions (owner only)
    os.chmod(cert_dir, 0o700)

    return cert_dir


def save_certificate_files(
    cert_pem: str,
    key_pem: str,
    ca_pem: str,
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
) -> None:
    """
    Save certificate files to disk with proper permissions.

    Args:
        cert_pem: Agent certificate in PEM format.
        key_pem: Agent private key in PEM format.
        ca_pem: CA certificate in PEM format.
        cert_path: Path to save agent certificate.
        key_path: Path to save agent private key.
        ca_path: Path to save CA certificate.
    """
    ensure_cert_directory()

    # Save agent certificate
    with open(cert_path, "w") as f:
        f.write(cert_pem)
    os.chmod(cert_path, 0o644)

    # Save private key (restrictive permissions)
    with open(key_path, "w") as f:
        f.write(key_pem)
    os.chmod(key_path, 0o600)

    # Save CA certificate
    with open(ca_path, "w") as f:
        f.write(ca_pem)
    os.chmod(ca_path, 0o644)

    logger.info(f"Saved certificate files to {cert_path.parent}")


def load_certificate_files(
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
) -> Dict[str, str]:
    """
    Load certificate files from disk.

    Args:
        cert_path: Path to agent certificate.
        key_path: Path to agent private key.
        ca_path: Path to CA certificate.

    Returns:
        Dict with certificate, key, and CA PEM strings.

    Raises:
        MTLSError: If files cannot be loaded.
    """
    try:
        with open(cert_path, "r") as f:
            cert_pem = f.read()
        with open(key_path, "r") as f:
            key_pem = f.read()
        with open(ca_path, "r") as f:
            ca_pem = f.read()

        return {
            "certificate": cert_pem,
            "private_key": key_pem,
            "ca_certificate": ca_pem,
        }
    except FileNotFoundError as e:
        raise MTLSError(f"Certificate file not found: {e}")
    except Exception as e:
        raise MTLSError(f"Failed to load certificates: {e}")


def certificates_exist(
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
) -> bool:
    """
    Check if all certificate files exist.

    Returns:
        True if all files exist.
    """
    return cert_path.exists() and key_path.exists() and ca_path.exists()


def create_ssl_context(
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
    verify_server: bool = True,
) -> ssl.SSLContext:
    """
    Create an SSL context for mTLS connections.

    Args:
        cert_path: Path to agent certificate.
        key_path: Path to agent private key.
        ca_path: Path to CA certificate.
        verify_server: Whether to verify the server certificate.

    Returns:
        Configured SSL context.

    Raises:
        MTLSError: If SSL context cannot be created.
    """
    try:
        # Create SSL context for client authentication
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load client certificate and key
        ctx.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )

        # Load CA certificate for server verification
        if verify_server:
            ctx.load_verify_locations(cafile=str(ca_path))
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
        else:
            ctx.verify_mode = ssl.CERT_NONE
            ctx.check_hostname = False

        # Security settings
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")

        logger.info("Created mTLS SSL context")
        return ctx

    except ssl.SSLError as e:
        raise MTLSError(f"SSL error creating context: {e}")
    except Exception as e:
        raise MTLSError(f"Failed to create SSL context: {e}")


def get_websocket_ssl_options(
    cert_path: Path = DEFAULT_CERT_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    ca_path: Path = DEFAULT_CA_PATH,
    verify_server: bool = True,
) -> Dict[str, Any]:
    """
    Get SSL options for websocket-client library.

    Args:
        cert_path: Path to agent certificate.
        key_path: Path to agent private key.
        ca_path: Path to CA certificate.
        verify_server: Whether to verify the server certificate.

    Returns:
        Dict with SSL options for websocket.WebSocketApp.
    """
    ssl_context = create_ssl_context(cert_path, key_path, ca_path, verify_server)

    return {
        "context": ssl_context,
    }


# =============================================================================
# Agent Configuration
# =============================================================================


def save_agent_config(
    agent_uuid: str,
    server_url: str,
    additional_config: Optional[Dict[str, Any]] = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> None:
    """
    Save agent configuration.

    Args:
        agent_uuid: The agent's UUID.
        server_url: The server WebSocket URL.
        additional_config: Additional configuration options.
        config_path: Path to save configuration.
    """
    config = {
        "agent_uuid": agent_uuid,
        "server_url": server_url,
        "machine_fingerprint": get_machine_fingerprint(),
    }

    if additional_config:
        config.update(additional_config)

    ensure_cert_directory()

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    # Restrictive permissions
    os.chmod(config_path, 0o600)

    logger.info(f"Saved agent config to {config_path}")


def load_agent_config(config_path: Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load agent configuration.

    Args:
        config_path: Path to configuration file.

    Returns:
        Configuration dictionary.

    Raises:
        MTLSError: If configuration cannot be loaded.
    """
    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        # Verify machine fingerprint
        current_fingerprint = get_machine_fingerprint()
        stored_fingerprint = config.get("machine_fingerprint")

        if stored_fingerprint and stored_fingerprint != current_fingerprint:
            logger.warning("Machine fingerprint mismatch - certificates may need reissuing")

        return config

    except FileNotFoundError:
        raise MTLSError("Agent configuration not found")
    except json.JSONDecodeError as e:
        raise MTLSError(f"Invalid configuration file: {e}")
    except Exception as e:
        raise MTLSError(f"Failed to load configuration: {e}")


def config_exists(config_path: Path = DEFAULT_CONFIG_PATH) -> bool:
    """
    Check if agent configuration exists.

    Returns:
        True if configuration file exists.
    """
    return config_path.exists()


# =============================================================================
# Certificate Registration
# =============================================================================


async def register_agent_certificate(
    server_url: str,
    installation_key: str,
    agent_info: Dict[str, Any],
) -> Dict[str, str]:
    """
    Register a new agent and obtain certificates.

    Args:
        server_url: The server API URL (https://...).
        installation_key: The installation key for registration.
        agent_info: Agent information (hostname, os, arch, etc.).

    Returns:
        Dict with certificate_pem, private_key_pem, ca_certificate_pem.

    Raises:
        MTLSError: If registration fails.
    """
    import httpx

    try:
        async with httpx.AsyncClient(verify=False) as client:  # Initial registration doesn't have CA yet
            # First, validate the installation key
            validate_response = await client.post(
                f"{server_url}/api/v1/pki/installation-keys/validate",
                params={"key": installation_key},
            )

            if validate_response.status_code != 200:
                raise MTLSError("Failed to validate installation key")

            validation = validate_response.json()
            if not validation.get("valid"):
                raise MTLSError("Invalid installation key")

            # Register the agent
            register_response = await client.post(
                f"{server_url}/api/agents/register",
                json={
                    "installation_key": installation_key,
                    **agent_info,
                },
            )

            if register_response.status_code != 200:
                error = register_response.json().get("detail", "Registration failed")
                raise MTLSError(f"Agent registration failed: {error}")

            registration = register_response.json()
            agent_uuid = registration.get("uuid")

            if not agent_uuid:
                raise MTLSError("No UUID in registration response")

            # Request certificate
            cert_response = await client.post(
                f"{server_url}/api/v1/pki/certificates",
                json={"agent_uuid": agent_uuid},
                headers={"Authorization": f"Bearer {registration.get('token', '')}"},
            )

            if cert_response.status_code != 200:
                raise MTLSError("Failed to obtain certificate")

            cert_data = cert_response.json()

            return {
                "agent_uuid": agent_uuid,
                "certificate_pem": cert_data["certificate_pem"],
                "private_key_pem": cert_data["private_key_pem"],
                "ca_certificate_pem": cert_data["ca_certificate_pem"],
            }

    except httpx.RequestError as e:
        raise MTLSError(f"Network error during registration: {e}")
    except Exception as e:
        if isinstance(e, MTLSError):
            raise
        raise MTLSError(f"Registration failed: {e}")


def setup_agent_mtls(
    agent_uuid: str,
    server_url: str,
    cert_pem: str,
    key_pem: str,
    ca_pem: str,
) -> None:
    """
    Complete setup of agent mTLS.

    Saves all certificates and configuration.

    Args:
        agent_uuid: The agent's UUID.
        server_url: The server WebSocket URL.
        cert_pem: Agent certificate PEM.
        key_pem: Agent private key PEM.
        ca_pem: CA certificate PEM.
    """
    # Save certificates
    save_certificate_files(cert_pem, key_pem, ca_pem)

    # Save configuration
    save_agent_config(agent_uuid, server_url)

    logger.info(f"Agent mTLS setup complete for {agent_uuid}")


def is_mtls_configured() -> bool:
    """
    Check if mTLS is fully configured.

    Returns:
        True if all certificates and config exist.
    """
    return certificates_exist() and config_exists()
