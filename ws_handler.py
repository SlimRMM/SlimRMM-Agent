import base64
import websocket
import json
import zipfile
import shutil
import logging
import subprocess
import platform
import threading
import stat
import pwd
import time
import grp
import select
import asyncio
import os
import sys
import ssl
import tempfile
from pathlib import Path
from typing import Set, Dict, Any, Union, Optional

from osquery_handler import run_osquery_query
from service_utils import uninstall_service, is_admin, uninstall_software, get_install_dir
from config import load_config


def get_available_updates() -> list:
    """
    Get available system updates for the current platform.
    Returns a list of dicts with 'name', 'version', and 'desc' fields.
    """
    system = platform.system()
    updates = []

    try:
        if system == 'Linux':
            updates = _get_linux_updates()
        elif system == 'Darwin':
            updates = _get_macos_updates()
        elif system == 'Windows':
            updates = _get_windows_updates()
    except Exception as e:
        logging.error(f"Error getting available updates: {e}")

    return updates


def _get_linux_updates() -> list:
    """Get available updates on Linux using apt or dnf/yum."""
    updates = []

    # Try apt (Debian/Ubuntu)
    if shutil.which('apt'):
        try:
            # Update package lists first (may need sudo, so just try)
            subprocess.run(['apt', 'update'], capture_output=True, timeout=60)
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    # Skip header line "Listing..."
                    if line.startswith('Listing') or not line.strip():
                        continue
                    # Format: package/suite version arch [upgradable from: old_version]
                    try:
                        parts = line.split('/')
                        if len(parts) >= 2:
                            pkg_name = parts[0]
                            rest = parts[1]
                            version_parts = rest.split()
                            new_version = version_parts[1] if len(version_parts) > 1 else ''
                            old_version = ''
                            if 'upgradable from:' in line:
                                old_version = line.split('upgradable from:')[1].strip().rstrip(']')
                            updates.append({
                                'name': pkg_name,
                                'version': new_version,
                                'desc': f"Upgrade from {old_version}" if old_version else "Available update"
                            })
                    except Exception as e:
                        logging.debug(f"Error parsing apt line '{line}': {e}")
                        continue
        except subprocess.TimeoutExpired:
            logging.warning("apt list --upgradable timed out")
        except Exception as e:
            logging.error(f"Error running apt: {e}")

    # Try dnf (Fedora/RHEL 8+)
    elif shutil.which('dnf'):
        try:
            result = subprocess.run(
                ['dnf', 'check-update', '-q'],
                capture_output=True,
                text=True,
                timeout=60
            )
            # dnf returns exit code 100 if updates are available, 0 if none
            if result.returncode in [0, 100]:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if not line.strip():
                        continue
                    # Format: package.arch  version  repo
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name = parts[0].rsplit('.', 1)[0]  # Remove arch suffix
                        version = parts[1]
                        repo = parts[2] if len(parts) > 2 else ''
                        updates.append({
                            'name': pkg_name,
                            'version': version,
                            'desc': f"Available from {repo}" if repo else "Available update"
                        })
        except subprocess.TimeoutExpired:
            logging.warning("dnf check-update timed out")
        except Exception as e:
            logging.error(f"Error running dnf: {e}")

    # Try yum (RHEL/CentOS 7)
    elif shutil.which('yum'):
        try:
            result = subprocess.run(
                ['yum', 'check-update', '-q'],
                capture_output=True,
                text=True,
                timeout=60
            )
            # yum returns exit code 100 if updates are available, 0 if none
            if result.returncode in [0, 100]:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if not line.strip():
                        continue
                    # Format: package.arch  version  repo
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg_name = parts[0].rsplit('.', 1)[0]  # Remove arch suffix
                        version = parts[1]
                        repo = parts[2] if len(parts) > 2 else ''
                        updates.append({
                            'name': pkg_name,
                            'version': version,
                            'desc': f"Available from {repo}" if repo else "Available update"
                        })
        except subprocess.TimeoutExpired:
            logging.warning("yum check-update timed out")
        except Exception as e:
            logging.error(f"Error running yum: {e}")

    return updates


def _get_macos_updates() -> list:
    """Get available updates on macOS using softwareupdate."""
    updates = []

    try:
        result = subprocess.run(
            ['softwareupdate', '-l'],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            current_update = None
            for line in lines:
                line = line.strip()
                if line.startswith('* Label:'):
                    if current_update:
                        updates.append(current_update)
                    label = line.replace('* Label:', '').strip()
                    current_update = {'name': label, 'version': '', 'desc': ''}
                elif line.startswith('Title:') and current_update:
                    current_update['desc'] = line.replace('Title:', '').strip()
                elif line.startswith('Version:') and current_update:
                    current_update['version'] = line.replace('Version:', '').strip()
            if current_update:
                updates.append(current_update)
    except subprocess.TimeoutExpired:
        logging.warning("softwareupdate -l timed out")
    except Exception as e:
        logging.error(f"Error running softwareupdate: {e}")

    # Also check Homebrew if available
    if shutil.which('brew'):
        try:
            result = subprocess.run(
                ['brew', 'outdated', '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                import json as brew_json
                try:
                    outdated = brew_json.loads(result.stdout)
                    if isinstance(outdated, dict):
                        # Handle formulae
                        for formula in outdated.get('formulae', []):
                            name = formula.get('name', '')
                            current = formula.get('installed_versions', [''])[0] if formula.get('installed_versions') else ''
                            latest = formula.get('current_version', '')
                            updates.append({
                                'name': f"brew:{name}",
                                'version': latest,
                                'desc': f"Upgrade from {current}" if current else "Available update"
                            })
                        # Handle casks
                        for cask in outdated.get('casks', []):
                            name = cask.get('name', '')
                            current = cask.get('installed_versions', '')
                            latest = cask.get('current_version', '')
                            updates.append({
                                'name': f"brew-cask:{name}",
                                'version': latest,
                                'desc': f"Upgrade from {current}" if current else "Available update"
                            })
                except Exception as je:
                    logging.debug(f"Error parsing brew outdated JSON: {je}")
        except subprocess.TimeoutExpired:
            logging.warning("brew outdated timed out")
        except Exception as e:
            logging.debug(f"Error running brew outdated: {e}")

    return updates


# External IP caching
_external_ip_cache = {
    'ip': None,
    'last_fetch': 0
}
EXTERNAL_IP_FETCH_INTERVAL = 900  # 15 minutes in seconds


def get_external_ip() -> str:
    """
    Fetch external IP from ifconfig.io/ip.
    Caches result for 15 minutes to avoid excessive requests.
    """
    import urllib.request

    current_time = time.time()

    # Return cached IP if still valid
    if (_external_ip_cache['ip'] and
        (current_time - _external_ip_cache['last_fetch']) < EXTERNAL_IP_FETCH_INTERVAL):
        return _external_ip_cache['ip']

    try:
        # Use ifconfig.io/ip to get external IP
        req = urllib.request.Request(
            'https://ifconfig.io/ip',
            headers={'User-Agent': 'SlimRMM-Agent/1.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            external_ip = response.read().decode('utf-8').strip()

        # Validate IP format (basic check)
        if external_ip and ('.' in external_ip or ':' in external_ip):
            _external_ip_cache['ip'] = external_ip
            _external_ip_cache['last_fetch'] = current_time
            logging.debug(f"Fetched external IP: {external_ip}")
            return external_ip

    except Exception as e:
        logging.debug(f"Failed to fetch external IP: {e}")

    # Return cached IP even if expired, or None
    return _external_ip_cache.get('ip')


def _get_windows_updates() -> list:
    """Get available updates on Windows using PowerShell/COM."""
    updates = []

    try:
        # Use PowerShell to query Windows Update
        ps_script = '''
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
try {
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
    foreach($Update in $SearchResult.Updates) {
        [PSCustomObject]@{
            Title = $Update.Title
            KB = if($Update.KBArticleIDs.Count -gt 0) { "KB" + $Update.KBArticleIDs[0] } else { "" }
            Description = $Update.Description
        }
    }
} catch {
    # Silently fail if Windows Update service is not available
}
'''
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_script],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode == 0 and result.stdout.strip():
            # Parse PowerShell output
            lines = result.stdout.strip().split('\n')
            current_update = {}
            for line in lines:
                line = line.strip()
                if line.startswith('Title'):
                    if current_update and current_update.get('Title'):
                        updates.append({
                            'name': current_update.get('Title', ''),
                            'version': current_update.get('KB', ''),
                            'desc': current_update.get('Description', '')[:200] if current_update.get('Description') else ''
                        })
                    current_update = {}
                if ':' in line:
                    key, _, value = line.partition(':')
                    current_update[key.strip()] = value.strip()
            # Don't forget last one
            if current_update and current_update.get('Title'):
                updates.append({
                    'name': current_update.get('Title', ''),
                    'version': current_update.get('KB', ''),
                    'desc': current_update.get('Description', '')[:200] if current_update.get('Description') else ''
                })
    except subprocess.TimeoutExpired:
        logging.warning("Windows Update query timed out")
    except Exception as e:
        logging.error(f"Error querying Windows Updates: {e}")

    return updates


def get_certificate_serial_number() -> Optional[str]:
    """
    Get the serial number from the current agent certificate.

    Returns:
        Serial number as hex string, or None if certificate doesn't exist.
    """
    from cryptography import x509

    install_dir = get_install_dir()
    cert_path = os.path.join(install_dir, 'certs', 'agent.crt')

    if not os.path.exists(cert_path):
        return None

    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        return format(cert.serial_number, 'x')
    except Exception as e:
        logging.error(f"Error reading certificate serial: {e}")
        return None


def check_certificate_expiry() -> dict:
    """
    Check if the agent certificate is expiring soon.

    Returns:
        Dict with expiry information: days_until_expiry, needs_renewal, is_expired
    """
    from cryptography import x509
    from datetime import datetime, timezone

    install_dir = get_install_dir()
    cert_path = os.path.join(install_dir, 'certs', 'agent.crt')

    if not os.path.exists(cert_path):
        return {
            "has_certificate": False,
            "needs_renewal": True,
            "days_until_expiry": 0,
        }

    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)

        now = datetime.now(timezone.utc)
        expiry = cert.not_valid_after_utc
        days_until_expiry = (expiry - now).days

        # Recommend renewal if less than 30 days until expiry
        needs_renewal = days_until_expiry <= 30

        return {
            "has_certificate": True,
            "serial_number": format(cert.serial_number, 'x'),
            "not_after": expiry.isoformat(),
            "days_until_expiry": days_until_expiry,
            "needs_renewal": needs_renewal,
            "is_expired": days_until_expiry < 0,
        }
    except Exception as e:
        logging.error(f"Error checking certificate expiry: {e}")
        return {
            "has_certificate": True,
            "needs_renewal": True,
            "days_until_expiry": 0,
            "error": str(e),
        }


def renew_certificate(server_url: str, agent_uuid: str) -> bool:
    """
    Request a new certificate from the server.

    Args:
        server_url: Server URL (https://...)
        agent_uuid: Agent UUID

    Returns:
        True if renewal was successful.
    """
    import requests

    install_dir = get_install_dir()
    cert_path = os.path.join(install_dir, 'certs', 'agent.crt')
    key_path = os.path.join(install_dir, 'certs', 'agent.key')
    ca_path = os.path.join(install_dir, 'certs', 'ca.crt')

    current_serial = get_certificate_serial_number()
    if not current_serial:
        logging.error("Cannot renew: no current certificate found")
        return False

    try:
        logging.info(f"Requesting certificate renewal for agent {agent_uuid}")

        # Use current certificate for mTLS authentication during renewal
        response = requests.post(
            f"{server_url}/api/v1/pki/certificates/renew",
            json={
                "agent_uuid": agent_uuid,
                "current_serial_number": current_serial,
            },
            cert=(cert_path, key_path),
            verify=ca_path,
            timeout=30,
        )

        if response.status_code != 200:
            # Try without mTLS verification (for expired certs)
            logging.warning("mTLS renewal failed, trying without verification...")
            response = requests.post(
                f"{server_url}/api/v1/pki/certificates/renew",
                json={
                    "agent_uuid": agent_uuid,
                    "current_serial_number": current_serial,
                },
                verify=False,
                timeout=30,
            )

        response.raise_for_status()
        result = response.json()

        # Save new certificates
        certs_dir = os.path.join(install_dir, 'certs')
        os.makedirs(certs_dir, mode=0o700, exist_ok=True)

        # Save new agent certificate
        with open(cert_path, 'w') as f:
            f.write(result['certificate_pem'])
        os.chmod(cert_path, 0o644)

        # Save new private key
        with open(key_path, 'w') as f:
            f.write(result['private_key_pem'])
        os.chmod(key_path, 0o600)

        # Save CA certificate (in case it was updated)
        with open(ca_path, 'w') as f:
            f.write(result['ca_certificate_pem'])
        os.chmod(ca_path, 0o644)

        logging.info(f"Certificate renewed successfully. New serial: {result.get('serial_number')}")
        return True

    except requests.RequestException as e:
        logging.error(f"Failed to renew certificate: {e}")
        return False
    except Exception as e:
        logging.error(f"Error during certificate renewal: {e}")
        return False


def check_and_renew_certificate_if_needed(server_url: str, agent_uuid: str) -> bool:
    """
    Check certificate expiry and renew if needed.

    Should be called on agent startup and periodically.

    Args:
        server_url: Server URL
        agent_uuid: Agent UUID

    Returns:
        True if certificate is valid (either still valid or successfully renewed).
    """
    expiry_info = check_certificate_expiry()

    if not expiry_info.get("has_certificate"):
        logging.warning("No certificate found - agent may need reinstallation")
        return False

    if expiry_info.get("is_expired"):
        logging.warning(f"Certificate has EXPIRED! Attempting renewal...")
        return renew_certificate(server_url, agent_uuid)

    if expiry_info.get("needs_renewal"):
        days_left = expiry_info.get("days_until_expiry", 0)
        logging.info(f"Certificate expires in {days_left} days - renewing now...")
        return renew_certificate(server_url, agent_uuid)

    days_left = expiry_info.get("days_until_expiry", 0)
    logging.info(f"Certificate valid for {days_left} more days")
    return True


def get_mtls_ssl_context() -> Optional[ssl.SSLContext]:
    """
    Create SSL context for mTLS connection if certificates exist.

    Returns:
        SSLContext configured for mTLS, or None if certificates don't exist.
    """
    install_dir = get_install_dir()
    cert_path = os.path.join(install_dir, 'certs', 'agent.crt')
    key_path = os.path.join(install_dir, 'certs', 'agent.key')
    ca_path = os.path.join(install_dir, 'certs', 'ca.crt')

    # Check if all certificate files exist
    if not all(os.path.exists(p) for p in [cert_path, key_path, ca_path]):
        logging.info("mTLS certificates not found, using insecure connection")
        return None

    try:
        # Create SSL context for client authentication (mTLS)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Load client certificate and key for mTLS
        ctx.load_cert_chain(
            certfile=cert_path,
            keyfile=key_path,
        )

        # Load CA certificate for server verification
        ctx.load_verify_locations(cafile=ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # Server might use IP or different hostname

        # Security settings
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20")

        logging.info("mTLS SSL context created successfully")
        return ctx

    except ssl.SSLError as e:
        logging.error(f"SSL error creating mTLS context: {e}")
        return None
    except Exception as e:
        logging.error(f"Error creating mTLS SSL context: {e}")
        return None

# Remote Desktop module (optional)
try:
    from remote_desktop import (
        start_remote_desktop,
        stop_remote_desktop,
        handle_webrtc_answer,
        handle_ice_candidate,
        get_monitors,
        check_dependencies as check_rd_dependencies,
    )
    REMOTE_DESKTOP_AVAILABLE = True
except ImportError:
    REMOTE_DESKTOP_AVAILABLE = False
    logging.warning("Remote desktop module not available")

# Add src directory to path for security imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Security modules
from src.security.path_validator import (
    validate_path,
    PathValidationError,
    is_safe_filename,
    sanitize_filename,
)
from src.security.command_sandbox import (
    execute_safe_command,
    CommandNotAllowedError,
    CommandExecutionError,
)
from src.security.zip_handler import (
    safe_extract_zip,
    ZipSecurityError,
)

# Allowed paths for file operations
ALLOWED_FILE_PATHS: Set[str] = {
    "/home",
    "/Users",
    "/tmp",
    "/var/tmp",
    "/opt",
}

terminal_process = None
terminal_running = False
terminal_thread = None
master_fd = None
upload_chunks = {}

# Persistent event loop for async operations (especially WebRTC)
_async_loop = None
_async_thread = None


def _run_async_loop(loop):
    """Run the async event loop in a background thread."""
    asyncio.set_event_loop(loop)
    loop.run_forever()


def get_async_loop():
    """Get or create the persistent async event loop."""
    global _async_loop, _async_thread
    if _async_loop is None or not _async_loop.is_running():
        _async_loop = asyncio.new_event_loop()
        _async_thread = threading.Thread(target=_run_async_loop, args=(_async_loop,), daemon=True)
        _async_thread.start()
        # Give the loop a moment to start
        time.sleep(0.1)
    return _async_loop


def run_async(coro):
    """Run a coroutine on the persistent event loop and wait for result."""
    loop = get_async_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=30)  # 30 second timeout
    except Exception as e:
        logging.error(f"Async operation failed: {e}")
        raise


def start_websocket():
    config = load_config()
    server = config.get('server')
    agent_uuid = config.get('uuid')
    mtls_enabled = config.get('mtls_enabled', False)

    # Check and renew certificate if needed (30 days before expiry)
    if mtls_enabled:
        logging.info("Checking certificate expiry...")
        cert_valid = check_and_renew_certificate_if_needed(server, agent_uuid)
        if not cert_valid:
            logging.warning("Certificate check/renewal failed - will attempt connection anyway")

    # Determine WebSocket URL (wss for secure, ws for insecure)
    if server.startswith('https'):
        ws_url = f"{server.replace('https', 'wss')}/api/v1/ws/agent?uuid={agent_uuid}"
    else:
        ws_url = f"{server.replace('http', 'ws')}/api/v1/ws/agent?uuid={agent_uuid}"

    logging.info(f"Connecting to WebSocket: {ws_url}")

    # Get mTLS SSL context if certificates exist
    ssl_context = None
    sslopt = None
    if mtls_enabled:
        ssl_context = get_mtls_ssl_context()
        if ssl_context:
            sslopt = {"context": ssl_context}
            logging.info("Using mTLS for WebSocket connection")
        else:
            logging.warning("mTLS enabled but certificates not found, using insecure connection")
            sslopt = {"cert_reqs": ssl.CERT_NONE}  # Fall back to no verification
    else:
        # For non-mTLS connections (development/testing)
        sslopt = {"cert_reqs": ssl.CERT_NONE}
        logging.info("mTLS disabled, using insecure connection")

    # Track last certificate check time
    last_cert_check = [time.time()]  # Use list for mutable closure
    CERT_CHECK_INTERVAL = 86400  # Check every 24 hours

    def send_heartbeat(ws, interval=30):
        while True:
            try:
                # Include system stats with heartbeat
                stats = get_system_stats()

                # Fetch external IP (cached for 15 minutes)
                external_ip = get_external_ip()

                heartbeat_msg = json.dumps({
                    "action": "heartbeat",
                    "stats": stats,
                    "external_ip": external_ip
                })
                ws.send(heartbeat_msg)
                logging.debug(f"Sent heartbeat with stats: CPU={stats.get('cpu_percent', 0):.1f}%, Mem={stats.get('memory_percent', 0):.1f}%, ExtIP={external_ip}")

                # Periodic certificate check (every 24 hours)
                if mtls_enabled and (time.time() - last_cert_check[0]) >= CERT_CHECK_INTERVAL:
                    logging.info("Performing periodic certificate expiry check...")
                    cert_valid = check_and_renew_certificate_if_needed(server, agent_uuid)
                    last_cert_check[0] = time.time()
                    if cert_valid:
                        logging.info("Periodic certificate check passed")
                    else:
                        logging.warning("Certificate renewal may be needed - will retry on next check")

            except Exception as e:
                logging.error(f"Error sending heartbeat: {e}")
                break
            time.sleep(interval)

    async def on_message_async(ws, message):
        try:
            data = json.loads(message)
            action = data.get('action')
            logging.info(f"Received message: {message}")

            if action == 'run_osquery':
                query = data.get('query')
                scan_type = data.get('scan_type')
                request_id = data.get('request_id')  # Important: Pass back the request_id

                # Special handling for updates - use platform-specific commands instead of osquery
                if scan_type == 'updates':
                    result = get_available_updates()
                else:
                    result = run_osquery_query(query)

                response = {
                    "status": "success",
                    "action": "run_osquery",
                    "scan_type": scan_type,
                    "request_id": request_id,  # Include request_id in response
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'restart':
                logging.info("Restart command received.")
                execute_system_command('restart')
                response = {
                    "status": "success",
                    "action": "restart",
                    "message": "Restarting system."
                }
                ws.send(json.dumps(response))
            elif action == 'restart-force':
                logging.info("Restart command received.")
                execute_system_command('restart', True)
                response = {
                    "status": "success",
                    "action": "restart-force",
                    "message": "Restarting system."
                }
                ws.send(json.dumps(response))
            elif action == 'shutdown':
                logging.info("Shutdown command received.")
                execute_system_command('shutdown')
                response = {
                    "status": "success",
                    "action": "shutdown",
                    "message": "Shutting down system."
                }
                ws.send(json.dumps(response))
            elif action == 'shutdown-force':
                logging.info("Shutdown command received.")
                execute_system_command('shutdown', True)
                response = {
                    "status": "success",
                    "action": "shutdown-force",
                    "message": "Shutting down system."
                }
                ws.send(json.dumps(response))
            elif action == 'custom_command':
                command = data.get('command')
                logging.info(f"Executing custom command: {command}")
                result = execute_custom_command(command)
                response = {
                    "status": "success",
                    "action": "custom_command",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'start_terminal':
                if terminal_running:
                    logging.warning("Terminal already running. Attempting to stop and restart.. ")
                    stop_terminal()
                logging.info("Starting pseudo-terminal session.")
                start_terminal(ws)
            elif action == 'terminal_input':
                input_data = data.get('data')
                if terminal_running:
                    write_to_terminal(input_data)
                else:
                    ws.send(json.dumps({
                        "status": "error",
                        "action": "terminal_input",
                        "message": "Terminal not running."
                    }))
            elif action == 'stop_terminal':
                logging.info("Stopping pseudo-terminal session.")
                stop_terminal()
                ws.send(json.dumps({
                    "status": "success",
                    "action": "stop_terminal",
                    "message": "Terminal session stopped."
                }))
            elif action == 'ping':
                ws.send(json.dumps({
                    "status": "success",
                    "action": "pong"
                }))
            elif action == 'list_dir':
                dir_path = data.get('path', '/')
                logging.info(f"Listing directory: {dir_path}")
                try:
                    entries = []
                    with os.scandir(dir_path) as it:
                        for entry in it:
                            try:
                                info = entry.stat(follow_symlinks=False)
                                is_dir = entry.is_dir()
                                entry_data = {
                                    "name": entry.name,
                                    "path": entry.path,
                                    "type": "directory" if is_dir else "file",
                                    "size": info.st_size if not is_dir else None,
                                    "modified": time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(info.st_mtime)),
                                }
                                if platform.system() in ('Linux', 'Darwin'):
                                    try:
                                        entry_data["owner"] = pwd.getpwuid(info.st_uid).pw_name
                                        entry_data["group"] = grp.getgrgid(info.st_gid).gr_name
                                    except (KeyError, PermissionError):
                                        entry_data["owner"] = str(info.st_uid)
                                        entry_data["group"] = str(info.st_gid)
                                    entry_data["permissions"] = stat.filemode(info.st_mode)
                                elif platform.system() == 'Windows':
                                    try:
                                        import win32security
                                        sd = win32security.GetFileSecurity(entry.path,
                                                                           win32security.OWNER_SECURITY_INFORMATION)
                                        owner_sid = sd.GetSecurityDescriptorOwner()
                                        owner_name, _, _ = win32security.LookupAccountSid(None, owner_sid)
                                        entry_data["owner"] = owner_name
                                    except Exception:
                                        entry_data["owner"] = "Unknown"
                                    entry_data["permissions"] = oct(info.st_mode)
                                entries.append(entry_data)
                            except (PermissionError, OSError) as e:
                                # Skip entries we can't access
                                logging.debug(f"Cannot access {entry.name}: {e}")
                    # Sort: directories first, then files, both alphabetically
                    entries.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))
                    response = {
                        "action": "list_dir",
                        "data": {
                            "current_path": dir_path,
                            "entries": entries
                        }
                    }
                    logging.info(f"Sending list_dir response with {len(entries)} entries")
                    ws.send(json.dumps(response))
                except Exception as e:
                    logging.error(f"Error listing directory: {e}")
                    ws.send(json.dumps({
                        "status": "error",
                        "action": "list_dir",
                        "message": str(e)
                    }))
            elif action == 'create_folder':
                path = data.get('path')
                logging.info(f"Creating directory: {path}")
                result = create_directory(path)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "create_folder",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'delete_entry':
                path = data.get('path')
                logging.info(f"Deleting entry: {path}")
                result = delete_entry(path)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "delete_entry",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'rename_entry':
                old_path = data.get('old_path')
                new_path = data.get('new_path')
                logging.info(f"Renaming {old_path} to {new_path}")
                result = rename_entry(old_path, new_path)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "rename_entry",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'zip_entry':
                path = data.get('path')
                output = data.get('output')
                logging.info(f"Zipping {path} to {output}")
                result = zip_entry(path, output)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "zip_entry",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'unzip_entry':
                path = data.get('path')
                output = data.get('output')
                logging.info(f"Unzipping {path} to {output}")
                result = unzip_entry(path, output)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "unzip_entry",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'chmod':
                path = data.get('path')
                mode = data.get('mode')
                logging.info(f"Changing permissions of {path} to {mode}")
                result = chmod_entry(path, mode)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "chmod",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'chown':
                path = data.get('path')
                owner = data.get('owner')
                group = data.get('group')
                logging.info(f"Changing owner of {path} to {owner}:{group}")
                result = chown_entry(path, owner, group)
                response = {
                    "status": "success" if result.get("success") else "error",
                    "action": "chown",
                    "data": result
                }
                ws.send(json.dumps(response))
            elif action == 'download_file':
                path = data.get('path')
                logging.info(f"Downloading file: {path}")
                send_file_in_chunks(ws, path)
            elif action == 'upload_chunk':
                # Support new format from frontend: path, data, offset, is_last
                target_path = data.get('path')
                chunk_data = data.get('data')
                offset = data.get('offset', 0)
                is_last = data.get('is_last', False)

                if target_path and chunk_data is not None:
                    logging.info(f"Receiving upload chunk for {target_path} at offset {offset}, is_last={is_last}")
                    handle_upload_chunk_new(target_path, chunk_data, offset, is_last, ws)
                else:
                    # Legacy format support
                    filename = data.get('filename')
                    chunk_index = data.get('chunk_index')
                    total_chunks = data.get('total_chunks')
                    legacy_path = data.get('target_path')
                    if filename and chunk_index is not None:
                        logging.info(f"Receiving chunk {chunk_index + 1}/{total_chunks} for {filename}")
                        handle_upload_chunk(filename, chunk_index, total_chunks, chunk_data, legacy_path, ws)
            elif action == 'uninstall_software':
                package_name = data.get('package_name')
                app_path = data.get('app_path')
                if not package_name:
                    ws.send(json.dumps({
                        "status": "error",
                        "action": "uninstall_software",
                        "message": "Missing package_name."
                    }))
                    return
                logging.info(f"🗑️ Uninstall command received for package: {package_name} (app_path={app_path})")
                if is_admin():
                    try:
                        result = uninstall_software(package_name, app_path)
                        response = {
                            "status": "success" if result.get("success") else "error",
                            "action": "uninstall_software",
                            "package_name": package_name,
                            "app_path": app_path,
                            "data": result
                        }
                    except Exception as e:
                        logging.error(f"Error during uninstall: {e}")
                        response = {
                            "status": "error",
                            "action": "uninstall_software",
                            "message": str(e)
                        }
                else:
                    logging.warning("❌ Uninstall command received but not running as admin/root.")
                    response = {
                        "status": "error",
                        "action": "uninstall_software",
                        "message": "Not running as admin/root."
                    }
                ws.send(json.dumps(response))
            elif action == 'update_osquery':
                logging.info("🔄 osquery update command received.")
                if is_admin():
                    result = update_osquery()
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "update_osquery",
                        "data": result
                    }
                else:
                    logging.warning("❌ osquery update requires admin/root.")
                    response = {
                        "status": "error",
                        "action": "update_osquery",
                        "message": "Not running as admin/root."
                    }
                ws.send(json.dumps(response))
            elif action == 'update_agent':
                logging.info("🔄 Agent update command received.")
                server_url = data.get('server_url')
                if is_admin():
                    result = update_agent(server_url)
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "update_agent",
                        "data": result
                    }
                else:
                    logging.warning("❌ Agent update requires admin/root.")
                    response = {
                        "status": "error",
                        "action": "update_agent",
                        "message": "Not running as admin/root."
                    }
                ws.send(json.dumps(response))
            elif action.startswith('uninstall'):
                logging.info("🗑️ Received uninstall command via WebSocket.")
                if is_admin():
                    uninstall_service()
                else:
                    logging.warning("❌ Uninstall command received but not running as admin/root.")
            # Remote Desktop Actions
            elif action == 'get_monitors':
                logging.info("📺 Getting monitor list")
                if REMOTE_DESKTOP_AVAILABLE:
                    result = get_monitors()
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "get_monitors",
                        "data": result
                    }
                else:
                    response = {
                        "status": "error",
                        "action": "get_monitors",
                        "message": "Remote desktop not available"
                    }
                ws.send(json.dumps(response))
            elif action == 'check_remote_desktop':
                logging.info("🔍 Checking remote desktop dependencies")
                if REMOTE_DESKTOP_AVAILABLE:
                    deps = check_rd_dependencies()
                    response = {
                        "status": "success",
                        "action": "check_remote_desktop",
                        "data": deps
                    }
                else:
                    response = {
                        "status": "error",
                        "action": "check_remote_desktop",
                        "message": "Remote desktop module not installed",
                        "data": {"available": False}
                    }
                ws.send(json.dumps(response))
            elif action == 'start_remote_desktop':
                logging.info("🖥️ Starting remote desktop session")
                if REMOTE_DESKTOP_AVAILABLE:
                    session_id = data.get('session_id', str(time.time()))

                    async def send_to_frontend_async(msg):
                        ws.send(msg)

                    # Use await since we're already in async context
                    result = await start_remote_desktop(session_id, send_to_frontend_async)
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "start_remote_desktop",
                        "session_id": session_id,
                        "data": result
                    }
                else:
                    response = {
                        "status": "error",
                        "action": "start_remote_desktop",
                        "message": "Remote desktop not available"
                    }
                ws.send(json.dumps(response))
            elif action == 'stop_remote_desktop':
                logging.info("🛑 Stopping remote desktop session")
                if REMOTE_DESKTOP_AVAILABLE:
                    session_id = data.get('session_id')
                    result = await stop_remote_desktop(session_id)
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "stop_remote_desktop",
                        "data": result
                    }
                else:
                    response = {
                        "status": "error",
                        "action": "stop_remote_desktop",
                        "message": "Remote desktop not available"
                    }
                ws.send(json.dumps(response))
            elif action == 'webrtc_answer':
                logging.info("📡 Received WebRTC answer")
                if REMOTE_DESKTOP_AVAILABLE:
                    session_id = data.get('session_id')
                    answer = data.get('answer')
                    result = await handle_webrtc_answer(session_id, answer)
                    response = {
                        "status": "success" if result.get("success") else "error",
                        "action": "webrtc_answer",
                        "data": result
                    }
                else:
                    response = {
                        "status": "error",
                        "action": "webrtc_answer",
                        "message": "Remote desktop not available"
                    }
                ws.send(json.dumps(response))
            elif action == 'ice_candidate':
                logging.debug("🧊 Received ICE candidate")
                if REMOTE_DESKTOP_AVAILABLE:
                    session_id = data.get('session_id')
                    candidate = data.get('candidate')
                    await handle_ice_candidate(session_id, candidate)
                else:
                    logging.warning("ICE candidate received but remote desktop not available")
            elif action == 'get_system_stats':
                logging.debug("📊 Getting system stats")
                stats = get_system_stats()
                response = {
                    "action": "system_stats",
                    "data": stats
                }
                ws.send(json.dumps(response))
            else:
                logging.warning(f"Unknown action: {action}")
                ws.send(json.dumps({
                    "status": "error",
                    "action": action,
                    "message": f"Unknown action: {action}"
                }))
        except Exception as e:
            logging.error(f"Error processing message: {e}")
            ws.send(json.dumps({
                "status": "error",
                "action": "internal_error",
                "message": str(e)
            }))

    def on_message(ws, message):
        # Use persistent event loop for async operations (required for WebRTC)
        run_async(on_message_async(ws, message))

    def on_error(ws, error):
        logging.error(f"WebSocket error: {error}")

    def on_close(ws, close_status_code, close_msg):
        if upload_chunks:
            logging.info(f"Cleaning up incomplete uploads: {list(upload_chunks.keys())}")
            upload_chunks.clear()
        logging.warning(f"WebSocket closed: {close_status_code} - {close_msg}")

    def on_open(ws):
        logging.info("WebSocket connection established.")
        heartbeat_thread = threading.Thread(target=send_heartbeat, args=(ws,), daemon=True)
        heartbeat_thread.start()

    ws = websocket.WebSocketApp(
        ws_url,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
        on_open=on_open
    )

    while True:
        try:
            ws.run_forever(ping_interval=30, ping_timeout=20, sslopt=sslopt)
        except Exception as e:
            logging.error(f"WebSocket error: {e}")
        logging.info("Reconnecting in 5 seconds...")
        time.sleep(5)

# ---------- Hilfsfunktionen ----------

def execute_system_command(action, force=False):
    system = platform.system()
    try:
        if action == 'restart':
            if system == 'Linux':
                cmd = ['systemctl', 'reboot', '--force'] if force else ['systemctl', 'reboot']
            elif system == 'Darwin':
                cmd = ['shutdown', '-r', 'now']
            elif system == 'Windows':
                cmd = ['shutdown', '/r', '/t', '0']
                if force:
                    cmd.append('/f')
        elif action == 'shutdown':
            if system == 'Linux':
                cmd = ['systemctl', 'poweroff', '--force'] if force else ['systemctl', 'poweroff']
            elif system == 'Darwin':
                cmd = ['shutdown', '-h', 'now']
            elif system == 'Windows':
                cmd = ['shutdown', '/s', '/t', '0']
                if force:
                    cmd.append('/f')
        else:
            logging.warning(f"Unknown action: {action}")
            return
        logging.info(f"Executing: {' '.join(cmd)}")
        subprocess.Popen(cmd)
    except Exception as e:
        logging.error(f"Error executing {action}: {e}")

def execute_custom_command(command: str) -> Union[str, Dict[str, Any]]:
    """
    Execute a command safely without shell=True.

    Uses the command sandbox to validate and execute commands securely.
    Only whitelisted commands are allowed.
    """
    try:
        result = execute_safe_command(command)
        return result
    except CommandNotAllowedError as e:
        logging.warning(f"Command not allowed: {command}")
        return {"error": f"Command not allowed: {e}"}
    except CommandExecutionError as e:
        logging.error(f"Command execution failed: {e}")
        return {"error": str(e)}
    except Exception as e:
        logging.error(f"Error running custom command: {e}")
        return {"error": str(e)}

def find_available_shell():
    """
    Find the best available shell based on platform.
    - Linux: bash > zsh > sh
    - macOS: zsh (default on macOS)
    - Windows: PowerShell
    """
    import shutil

    system = platform.system()

    if system == 'Windows':
        # Windows uses PowerShell
        powershell = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
        if powershell:
            return powershell
        # Fallback to cmd
        return shutil.which('cmd.exe') or 'cmd.exe'

    if system == 'Darwin':
        # macOS default is zsh
        if os.path.exists('/bin/zsh'):
            return '/bin/zsh'
        # Check SHELL env as backup
        env_shell = os.environ.get('SHELL')
        if env_shell and os.path.exists(env_shell):
            return env_shell
        return '/bin/sh'

    # Linux: prefer bash > zsh > sh
    if system == 'Linux':
        # First check SHELL environment variable
        env_shell = os.environ.get('SHELL')
        if env_shell and os.path.exists(env_shell):
            return env_shell

        # Try shells in order of preference: bash, zsh, sh
        shells = ['/bin/bash', '/usr/bin/bash', '/bin/zsh', '/usr/bin/zsh', '/bin/sh', '/usr/bin/sh']
        for shell in shells:
            if os.path.exists(shell):
                return shell

    # Fallback to sh (should always exist)
    return '/bin/sh'

def start_terminal(ws):
    global terminal_process, terminal_running, terminal_thread, master_fd
    if terminal_running:
        logging.warning("Terminal already running.")
        return
    system = platform.system()
    if system in ['Linux', 'Darwin']:
        import pty
        master_fd, slave_fd = pty.openpty()
        shell = find_available_shell()
        logging.info(f"Starting terminal with shell: {shell}")
        cwd = '/root' if os.path.exists('/root') else os.path.expanduser('~')
        terminal_process = subprocess.Popen(
            [shell],
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            universal_newlines=True,
            env={**os.environ, 'TERM': 'xterm-256color'},
            cwd=cwd
        )
        terminal_running = True
        def read_from_terminal():
            try:
                while terminal_running:
                    rlist, _, _ = select.select([master_fd], [], [], 0.1)
                    if rlist:
                        output = os.read(master_fd, 1024).decode(errors='ignore')
                        if output:
                            ws.send(json.dumps({"action": "terminal_output", "data": output}))
            except Exception as e:
                logging.error(f"Error reading from PTY: {e}")
        terminal_thread = threading.Thread(target=read_from_terminal, daemon=True)
        terminal_thread.start()
    else:
        ws.send(json.dumps({
            "status": "error",
            "action": "start_terminal",
            "message": f"Unsupported system: {system}"
        }))

def stop_terminal():
    global terminal_process, terminal_running, master_fd
    logging.info("Stopping existing terminal...")
    if terminal_process:
        try:
            terminal_process.terminate()
            terminal_process.wait(timeout=2)
            logging.info("Terminal process terminated.")
        except Exception as e:
            logging.error(f"Error terminating terminal: {e}")
        terminal_process = None
    master_fd = None
    terminal_running = False

def write_to_terminal(data):
    global master_fd
    try:
        if master_fd is not None:
            os.write(master_fd, data.encode())
    except Exception as e:
        logging.error(f"Error writing to terminal: {e}")

def create_directory(path: str) -> Dict[str, Any]:
    """Create a directory with path validation."""
    try:
        # Validate path is in allowed directories
        validated_path = validate_path(path, ALLOWED_FILE_PATHS)
        os.makedirs(validated_path, exist_ok=False)
        return {"success": True, "path": str(validated_path)}
    except PathValidationError as e:
        logging.warning(f"Path validation failed for create_directory: {path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except FileExistsError:
        return {"success": False, "error": "Directory already exists."}
    except Exception as e:
        logging.error(f"Error creating directory: {e}")
        return {"success": False, "error": str(e)}

def delete_entry(path: str) -> Dict[str, Any]:
    """Delete a file or directory with path validation."""
    try:
        # Validate path is in allowed directories
        validated_path = validate_path(path, ALLOWED_FILE_PATHS, check_exists=True)

        if validated_path.is_dir():
            shutil.rmtree(validated_path)
            return {"success": True, "type": "dir", "path": str(validated_path)}
        elif validated_path.is_file():
            os.remove(validated_path)
            return {"success": True, "type": "file", "path": str(validated_path)}
        else:
            return {"success": False, "error": "Path does not exist or unsupported type."}
    except PathValidationError as e:
        logging.warning(f"Path validation failed for delete_entry: {path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except Exception as e:
        logging.error(f"Error deleting entry: {e}")
        return {"success": False, "error": str(e)}

def rename_entry(old_path: str, new_path: str) -> Dict[str, Any]:
    """Rename a file or directory with path validation."""
    try:
        # Validate both paths are in allowed directories
        validated_old = validate_path(old_path, ALLOWED_FILE_PATHS, check_exists=True)
        validated_new = validate_path(new_path, ALLOWED_FILE_PATHS)

        os.rename(validated_old, validated_new)
        return {
            "success": True,
            "old_path": str(validated_old),
            "new_path": str(validated_new),
        }
    except PathValidationError as e:
        logging.warning(f"Path validation failed for rename_entry: {old_path} -> {new_path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except Exception as e:
        logging.error(f"Error renaming entry: {e}")
        return {"success": False, "error": str(e)}

def chmod_entry(path: str, mode: str) -> Dict[str, Any]:
    """Change file/directory permissions with path validation."""
    try:
        # Validate path is in allowed directories
        validated_path = validate_path(path, ALLOWED_FILE_PATHS, check_exists=True)

        # Convert octal string to integer (e.g., "755" -> 0o755)
        mode_int = int(mode, 8)
        os.chmod(validated_path, mode_int)
        return {
            "success": True,
            "path": str(validated_path),
            "mode": mode,
        }
    except PathValidationError as e:
        logging.warning(f"Path validation failed for chmod_entry: {path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except ValueError as e:
        logging.error(f"Invalid mode format: {mode}")
        return {"success": False, "error": f"Invalid mode format: {mode}"}
    except Exception as e:
        logging.error(f"Error changing permissions: {e}")
        return {"success": False, "error": str(e)}

def chown_entry(path: str, owner: str = None, group: str = None) -> Dict[str, Any]:
    """Change file/directory owner and/or group with path validation."""
    try:
        import pwd
        import grp

        # Validate path is in allowed directories
        validated_path = validate_path(path, ALLOWED_FILE_PATHS, check_exists=True)

        # Get current uid/gid
        stat_info = os.stat(validated_path)
        uid = stat_info.st_uid
        gid = stat_info.st_gid

        # Resolve owner to UID
        if owner:
            try:
                uid = int(owner)
            except ValueError:
                uid = pwd.getpwnam(owner).pw_uid

        # Resolve group to GID
        if group:
            try:
                gid = int(group)
            except ValueError:
                gid = grp.getgrnam(group).gr_gid

        os.chown(validated_path, uid, gid)
        return {
            "success": True,
            "path": str(validated_path),
            "owner": owner,
            "group": group,
        }
    except PathValidationError as e:
        logging.warning(f"Path validation failed for chown_entry: {path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except KeyError as e:
        logging.error(f"User or group not found: {e}")
        return {"success": False, "error": f"User or group not found: {e}"}
    except PermissionError as e:
        logging.error(f"Permission denied for chown: {e}")
        return {"success": False, "error": "Permission denied. Root privileges required."}
    except Exception as e:
        logging.error(f"Error changing owner: {e}")
        return {"success": False, "error": str(e)}

def zip_entry(source_path: str, output_zip: str) -> Dict[str, Any]:
    """Create a ZIP archive with path validation."""
    try:
        # Validate both paths
        validated_source = validate_path(source_path, ALLOWED_FILE_PATHS, check_exists=True)
        validated_output = validate_path(output_zip, ALLOWED_FILE_PATHS)

        with zipfile.ZipFile(validated_output, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if validated_source.is_file():
                arcname = validated_source.name
                zipf.write(validated_source, arcname)
            else:
                for root, _, files in os.walk(validated_source):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(validated_source)
                        zipf.write(file_path, arcname)
        return {"success": True, "output": str(validated_output)}
    except PathValidationError as e:
        logging.warning(f"Path validation failed for zip_entry: {source_path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except Exception as e:
        logging.error(f"Error zipping: {e}")
        return {"success": False, "error": str(e)}


def unzip_entry(zip_path: str, extract_to: str) -> Dict[str, Any]:
    """
    Extract a ZIP archive safely with ZIP-Slip prevention.

    Uses the secure ZIP handler to validate all archive members.
    """
    try:
        # Validate both paths
        validated_zip = validate_path(zip_path, ALLOWED_FILE_PATHS, check_exists=True)
        validated_extract = validate_path(extract_to, ALLOWED_FILE_PATHS)

        # Use secure extraction
        result = safe_extract_zip(str(validated_zip), str(validated_extract))
        return result
    except PathValidationError as e:
        logging.warning(f"Path validation failed for unzip_entry: {zip_path}")
        return {"success": False, "error": f"Access denied: {e}"}
    except ZipSecurityError as e:
        logging.warning(f"ZIP security violation: {e}")
        return {"success": False, "error": f"Security violation: {e}"}
    except Exception as e:
        logging.error(f"Error unzipping: {e}")
        return {"success": False, "error": str(e)}

def send_file_in_chunks(ws, path, chunk_size=1024*1024):
    if not os.path.exists(path) or not os.path.isfile(path):
        ws.send(json.dumps({
            "status": "error",
            "action": "download_file",
            "message": "File does not exist."
        }))
        return
    try:
        filesize = os.path.getsize(path)
        total_chunks = (filesize + chunk_size - 1) // chunk_size
        filename = os.path.basename(path)
        with open(path, 'rb') as f:
            for chunk_index in range(total_chunks):
                chunk = f.read(chunk_size)
                encoded_chunk = base64.b64encode(chunk).decode()
                ws.send(json.dumps({
                    "action": "download_chunk",
                    "status": "success",
                    "filename": filename,
                    "chunk_index": chunk_index,
                    "total_chunks": total_chunks,
                    "data": encoded_chunk
                }))
        logging.info(f"Finished sending {filename} in {total_chunks} chunks.")
    except Exception as e:
        logging.error(f"Error sending file: {e}")
        ws.send(json.dumps({
            "status": "error",
            "action": "download_file",
            "message": str(e)
        }))

def handle_upload_chunk(
    filename: str,
    chunk_index: int,
    total_chunks: int,
    data: str,
    target_path: str,
    ws,
) -> None:
    """
    Handle file upload chunks with path validation and filename sanitization.
    """
    try:
        # Validate target path
        validated_path = validate_path(target_path, ALLOWED_FILE_PATHS)

        # Sanitize filename
        safe_filename = sanitize_filename(filename)
        if safe_filename != filename:
            logging.warning(f"Filename sanitized: {filename} -> {safe_filename}")

        decoded_data = base64.b64decode(data)

        if safe_filename not in upload_chunks:
            upload_chunks[safe_filename] = {
                "chunks": {},
                "total_chunks": total_chunks,
                "target_path": str(validated_path),
            }

        upload_chunks[safe_filename]["chunks"][chunk_index] = decoded_data

        if len(upload_chunks[safe_filename]["chunks"]) == total_chunks:
            logging.info(f"All chunks received for {safe_filename}, assembling file...")

            # Write file with safe permissions
            with open(validated_path, 'wb') as f:
                for i in range(total_chunks):
                    f.write(upload_chunks[safe_filename]["chunks"][i])

            # Set safe permissions (no execute)
            os.chmod(validated_path, 0o644)

            del upload_chunks[safe_filename]
            ws.send(json.dumps({
                "status": "success",
                "action": "upload_complete",
                "filename": safe_filename,
                "target_path": str(validated_path),
            }))
        else:
            ws.send(json.dumps({
                "status": "success",
                "action": "upload_chunk_ack",
                "filename": safe_filename,
                "chunk_index": chunk_index,
                "total_chunks": total_chunks,
            }))

    except PathValidationError as e:
        logging.warning(f"Path validation failed for upload: {target_path}")
        ws.send(json.dumps({
            "status": "error",
            "action": "upload_chunk",
            "message": f"Access denied: {e}",
            "filename": filename,
            "chunk_index": chunk_index,
        }))
    except Exception as e:
        logging.error(f"Error handling upload chunk: {e}")
        ws.send(json.dumps({
            "status": "error",
            "action": "upload_chunk",
            "message": str(e),
            "filename": filename,
            "chunk_index": chunk_index,
        }))


def handle_upload_chunk_new(
    target_path: str,
    data: str,
    offset: int,
    is_last: bool,
    ws,
) -> None:
    """
    Handle file upload chunks using offset-based writing.
    This is the new format used by the frontend.
    """
    try:
        # Validate target path
        validated_path = validate_path(target_path, ALLOWED_FILE_PATHS)

        # Decode base64 data
        decoded_data = base64.b64decode(data)

        # Open file in read+write binary mode, create if not exists
        mode = 'r+b' if os.path.exists(validated_path) and offset > 0 else 'wb'
        with open(validated_path, mode) as f:
            f.seek(offset)
            f.write(decoded_data)

        if is_last:
            # Set safe permissions (no execute)
            os.chmod(validated_path, 0o644)
            filename = os.path.basename(target_path)
            logging.info(f"Upload complete: {target_path}")
            ws.send(json.dumps({
                "status": "success",
                "action": "upload_complete",
                "filename": filename,
                "target_path": str(validated_path),
                "data": {"success": True, "path": str(validated_path)},
            }))

    except PathValidationError as e:
        logging.warning(f"Path validation failed for upload: {target_path}")
        ws.send(json.dumps({
            "status": "error",
            "action": "upload_chunk",
            "message": f"Access denied: {e}",
        }))
    except Exception as e:
        logging.error(f"Error handling upload chunk: {e}")
        ws.send(json.dumps({
            "status": "error",
            "action": "upload_chunk",
            "message": str(e),
        }))


def get_system_stats() -> Dict[str, Any]:
    """
    Get current CPU and memory usage statistics using osquery.
    Works on Linux, macOS, and Windows.
    """
    from osquery_handler import run_osquery_query

    system = platform.system()

    try:
        # Get total physical memory and CPU cores from system_info
        sys_info = run_osquery_query("SELECT physical_memory, cpu_logical_cores FROM system_info;")

        memory_total = 0
        cpu_cores = 1

        if sys_info and not isinstance(sys_info, dict) and len(sys_info) > 0:
            memory_total = int(sys_info[0].get("physical_memory", 0))
            cpu_cores = int(sys_info[0].get("cpu_logical_cores", 1)) or 1

        # Get memory usage - platform specific
        memory_used = 0
        memory_percent = 0.0

        if system == 'Darwin':
            # macOS: Use virtual_memory_info (values in pages)
            page_size = 4096
            vm_info = run_osquery_query("SELECT free, active, inactive, wired FROM virtual_memory_info;")
            if vm_info and not isinstance(vm_info, dict) and len(vm_info) > 0:
                row = vm_info[0]
                active_pages = int(row.get("active", 0))
                wired_pages = int(row.get("wired", 0))
                memory_used = (active_pages + wired_pages) * page_size
                if memory_total > 0:
                    memory_percent = (memory_used / memory_total) * 100.0
        elif system == 'Linux':
            # Linux: Try osquery memory_info table first
            mem_info = run_osquery_query("SELECT memory_total, memory_free, buffers, cached FROM memory_info;")
            if mem_info and not isinstance(mem_info, dict) and len(mem_info) > 0:
                row = mem_info[0]
                mem_total = int(row.get("memory_total", 0))
                mem_free = int(row.get("memory_free", 0))
                buffers = int(row.get("buffers", 0))
                cached = int(row.get("cached", 0))
                # Used = Total - Free - Buffers - Cached
                memory_used = mem_total - mem_free - buffers - cached
                memory_total = mem_total
                if memory_total > 0:
                    memory_percent = (memory_used / memory_total) * 100.0

            # Fallback: Read directly from /proc/meminfo if osquery failed or returned 0
            if memory_percent == 0 and os.path.exists('/proc/meminfo'):
                try:
                    with open('/proc/meminfo', 'r') as f:
                        meminfo = {}
                        for line in f:
                            parts = line.split(':')
                            if len(parts) == 2:
                                key = parts[0].strip()
                                # Values are in kB, convert to bytes
                                value = int(parts[1].strip().split()[0]) * 1024
                                meminfo[key] = value

                        mem_total = meminfo.get('MemTotal', 0)
                        mem_free = meminfo.get('MemFree', 0)
                        buffers = meminfo.get('Buffers', 0)
                        cached = meminfo.get('Cached', 0)

                        memory_used = mem_total - mem_free - buffers - cached
                        memory_total = mem_total
                        if memory_total > 0:
                            memory_percent = (memory_used / memory_total) * 100.0
                            logging.debug(f"Linux memory from /proc/meminfo: {memory_percent:.1f}%")
                except Exception as e:
                    logging.error(f"Error reading /proc/meminfo: {e}")
        elif system == 'Windows':
            # Windows: Try WMI for memory info (more reliable than memory_info table)
            mem_info = run_osquery_query(
                "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM wmi_raw "
                "WHERE class = 'Win32_OperatingSystem' AND namespace = '\\\\root\\\\cimv2';"
            )
            if mem_info and not isinstance(mem_info, dict) and len(mem_info) > 0:
                row = mem_info[0]
                # WMI returns values in KB
                mem_total = int(row.get("TotalVisibleMemorySize", 0)) * 1024
                mem_free = int(row.get("FreePhysicalMemory", 0)) * 1024
                if mem_total > 0:
                    memory_used = mem_total - mem_free
                    memory_total = mem_total
                    memory_percent = (memory_used / memory_total) * 100.0

            # Fallback: Use system_info if WMI query failed
            if memory_percent == 0 and memory_total > 0:
                mem_available = run_osquery_query("SELECT available_physical_memory FROM system_info;")
                if mem_available and not isinstance(mem_available, dict) and len(mem_available) > 0:
                    avail = int(mem_available[0].get("available_physical_memory", 0))
                    if avail > 0:
                        memory_used = memory_total - avail
                        memory_percent = (memory_used / memory_total) * 100.0

        # Get CPU usage - platform specific
        cpu_percent = 0.0

        if system in ['Darwin', 'Linux']:
            # Use load average on macOS/Linux
            load_result = run_osquery_query("SELECT average FROM load_average WHERE period = '1m';")
            if load_result and not isinstance(load_result, dict) and len(load_result) > 0:
                load_avg = float(load_result[0].get("average", 0))
                cpu_percent = min((load_avg / cpu_cores) * 100.0, 100.0)
        elif system == 'Windows':
            # Windows: Use WMI for CPU usage
            cpu_result = run_osquery_query("SELECT percent_idle_time FROM wmi_cpu_speed LIMIT 1;")
            if cpu_result and not isinstance(cpu_result, dict) and len(cpu_result) > 0:
                idle = float(cpu_result[0].get("percent_idle_time", 100))
                cpu_percent = max(0, 100 - idle)

        return {
            "cpu_percent": round(cpu_percent, 1),
            "memory_percent": round(memory_percent, 1),
            "memory_used": memory_used,
            "memory_total": memory_total,
            "timestamp": int(time.time() * 1000),  # milliseconds
        }
    except Exception as e:
        logging.error(f"Error getting system stats via osquery: {e}")
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "memory_used": 0,
            "memory_total": 0,
            "timestamp": int(time.time() * 1000),
            "error": str(e)
        }


def update_osquery() -> Dict[str, Any]:
    """
    Update osquery to the latest version.

    Downloads and installs the latest osquery package for the current platform.
    """
    system = platform.system()

    try:
        if system == 'Darwin':
            # macOS: Use Homebrew if available, otherwise download pkg
            result = subprocess.run(
                ['brew', 'upgrade', 'osquery'],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                logging.info("osquery updated via Homebrew")
                return {"success": True, "message": "osquery updated via Homebrew", "output": result.stdout}
            else:
                # Try installing if not found
                result = subprocess.run(
                    ['brew', 'install', 'osquery'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    return {"success": True, "message": "osquery installed via Homebrew", "output": result.stdout}
                return {"success": False, "error": f"Homebrew failed: {result.stderr}"}

        elif system == 'Linux':
            # Linux: Check for package manager and update
            # Try apt first (Debian/Ubuntu)
            if shutil.which('apt-get'):
                # Add osquery repo if not present
                subprocess.run(['apt-get', 'update'], capture_output=True, timeout=120)
                result = subprocess.run(
                    ['apt-get', 'install', '-y', 'osquery'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    return {"success": True, "message": "osquery updated via apt", "output": result.stdout}
                return {"success": False, "error": f"apt failed: {result.stderr}"}

            # Try yum/dnf (RHEL/CentOS/Fedora)
            elif shutil.which('dnf') or shutil.which('yum'):
                pkg_manager = 'dnf' if shutil.which('dnf') else 'yum'
                result = subprocess.run(
                    [pkg_manager, 'install', '-y', 'osquery'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    return {"success": True, "message": f"osquery updated via {pkg_manager}", "output": result.stdout}
                return {"success": False, "error": f"{pkg_manager} failed: {result.stderr}"}
            else:
                return {"success": False, "error": "No supported package manager found (apt, dnf, yum)"}

        elif system == 'Windows':
            # Windows: Use chocolatey or winget
            if shutil.which('choco'):
                result = subprocess.run(
                    ['choco', 'upgrade', 'osquery', '-y'],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    shell=True
                )
                if result.returncode == 0:
                    return {"success": True, "message": "osquery updated via Chocolatey", "output": result.stdout}
                return {"success": False, "error": f"Chocolatey failed: {result.stderr}"}
            elif shutil.which('winget'):
                result = subprocess.run(
                    ['winget', 'upgrade', 'osquery.osquery'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    return {"success": True, "message": "osquery updated via winget", "output": result.stdout}
                return {"success": False, "error": f"winget failed: {result.stderr}"}
            else:
                return {"success": False, "error": "No supported package manager found (choco, winget)"}
        else:
            return {"success": False, "error": f"Unsupported platform: {system}"}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Update timed out after 5 minutes"}
    except Exception as e:
        logging.error(f"Error updating osquery: {e}")
        return {"success": False, "error": str(e)}


def update_agent(server_url: str = None) -> Dict[str, Any]:
    """
    Update the RMM agent to the latest version.

    Downloads the latest agent binary from the server and replaces the current one.
    Also renews the mTLS certificate to ensure secure connection after update.
    The agent service will be restarted after the update.
    """
    import urllib.request
    import ssl as ssl_module

    system = platform.system()
    config = load_config()

    if not server_url:
        server_url = config.get('server', '')

    if not server_url:
        return {"success": False, "error": "No server URL configured"}

    agent_uuid = config.get('uuid', '')
    mtls_enabled = config.get('mtls_enabled', False)

    # Renew certificate as part of update
    if mtls_enabled and agent_uuid:
        logging.info("Renewing certificate as part of agent update...")
        cert_renewed = renew_certificate(server_url, agent_uuid)
        if cert_renewed:
            logging.info("Certificate renewed successfully during update")
        else:
            logging.warning("Certificate renewal failed - continuing with update")

    try:
        # Determine platform for download
        if system == 'Darwin':
            platform_name = 'macos'
        elif system == 'Linux':
            platform_name = 'linux'
        else:
            return {"success": False, "error": f"Unsupported platform: {system}"}

        # Use the unauthenticated agent-update endpoint
        agent_uuid = config.get('uuid', '')
        download_url = f"{server_url}/api/v1/downloads/agent-update/{platform_name}?agent_uuid={agent_uuid}"

        # Find current agent binary location
        if system == 'Darwin':
            agent_path = Path('/var/lib/slimrmm/slimrmm-agent')
        elif system == 'Linux':
            agent_path = Path('/var/lib/slimrmm/slimrmm-agent')

        if not agent_path.exists():
            # Try to find agent in current directory
            agent_path = Path(sys.executable).parent / 'slimrmm-agent'

        # Create backup
        backup_path = agent_path.with_suffix('.backup')
        if agent_path.exists():
            shutil.copy2(agent_path, backup_path)
            logging.info(f"Created backup at {backup_path}")

        # Download new agent binary
        temp_path = Path(tempfile.gettempdir()) / 'rmm-agent-new'

        logging.info(f"Downloading agent from {download_url}")

        # Create SSL context (allow self-signed for development)
        ssl_ctx = ssl_module.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_module.CERT_NONE

        urllib.request.urlretrieve(download_url, temp_path)

        # Make executable
        os.chmod(temp_path, 0o755)

        # Replace agent binary
        shutil.move(str(temp_path), str(agent_path))
        os.chmod(agent_path, 0o755)

        logging.info(f"Agent binary updated at {agent_path}")

        # Schedule restart of agent service
        if system == 'Darwin':
            # macOS: Restart via launchctl
            subprocess.Popen(
                ['launchctl', 'kickstart', '-k', 'system/com.rmm.agent'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        elif system == 'Linux':
            # Linux: Restart via systemctl
            subprocess.Popen(
                ['systemctl', 'restart', 'rmm-agent'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

        return {
            "success": True,
            "message": "Agent updated successfully. Service will restart.",
            "path": str(agent_path)
        }

    except urllib.error.URLError as e:
        logging.error(f"Failed to download agent: {e}")
        return {"success": False, "error": f"Download failed: {e}"}
    except Exception as e:
        logging.error(f"Error updating agent: {e}")
        # Try to restore backup
        if 'backup_path' in locals() and backup_path.exists():
            try:
                shutil.copy2(backup_path, agent_path)
                logging.info("Restored agent from backup")
            except Exception as restore_err:
                logging.error(f"Failed to restore backup: {restore_err}")
        return {"success": False, "error": str(e)}