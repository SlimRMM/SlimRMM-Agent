"""
SlimRMM Agent - Service Utilities
Copyright (c) 2025 Kiefer Networks

Provides utility functions for service management, installation, and uninstallation.
"""

import os
import subprocess
import platform
import shutil
import json
import logging
import sys
import requests
from pathlib import Path
import plistlib

# SlimRMM Configuration
INSTALL_DIR_UNIX = '/var/lib/slimrmm'
INSTALL_DIR_WINDOWS = r'C:\Program Files\SlimRMM'
LAUNCHD_LABEL = 'io.slimrmm.agent'
SYSTEMD_SERVICE = 'slimrmm-agent'
WINDOWS_SERVICE = 'SlimRMM_Agent'
CONFIG_FILENAME = '.slimrmm_config.json'


def get_install_dir():
    """Get the installation directory for the current platform."""
    system = platform.system()
    if system in ['Linux', 'Darwin']:
        return INSTALL_DIR_UNIX
    elif system == 'Windows':
        return INSTALL_DIR_WINDOWS
    else:
        raise Exception(f"Unsupported OS: {system}")


def get_config_path():
    """Get the full path to the configuration file."""
    return os.path.join(get_install_dir(), CONFIG_FILENAME)


def is_admin():
    """Check if the current process has administrator/root privileges."""
    system = platform.system()
    if system == 'Windows':
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def uninstall_service():
    """Uninstall the SlimRMM agent service and clean up all files."""
    if not is_admin():
        print("You need to run this script as administrator/root.")
        sys.exit(1)

    system = platform.system()
    target_dir = get_install_dir()
    logging.info(f"Uninstalling SlimRMM Agent on {system}")

    try:
        # Deregister from server
        config_path = get_config_path()
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                server = config.get('server')
                uuid = config.get('uuid')
                api_key = config.get('api_key')

            if server and uuid and api_key:
                try:
                    url = f"{server}/api/v1/agents/{uuid}"
                    logging.info(f"Deregistering agent from server: {url}")
                    response = requests.delete(url, headers={"Authorization": f"Bearer {api_key}"})
                    if response.status_code == 200:
                        logging.info("Successfully deregistered agent from server.")
                    else:
                        logging.warning(f"Failed to deregister agent: {response.status_code}")
                except Exception as e:
                    logging.error(f"Error deregistering agent: {e}")
            else:
                logging.warning("Missing server, uuid or api_key in config. Skipping deregistration.")

        # Stop and remove service based on platform
        if system == 'Linux':
            _uninstall_linux_service()
        elif system == 'Darwin':
            _uninstall_macos_service()
        elif system == 'Windows':
            _uninstall_windows_service()

        # Remove symlink if present
        if system in ['Linux', 'Darwin']:
            symlinks = ['/usr/local/bin/slimrmm-agent', '/usr/local/bin/agent']
            for symlink in symlinks:
                if os.path.exists(symlink):
                    os.remove(symlink)
                    logging.info(f"Removed symlink: {symlink}")

        # Remove installation directory
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
            logging.info(f"Removed installation directory: {target_dir}")

        # Also clean up old RMM installation if exists
        old_dir = '/var/lib/rmm'
        if os.path.exists(old_dir):
            shutil.rmtree(old_dir)
            logging.info(f"Removed legacy installation: {old_dir}")

        logging.info("Uninstallation complete.")

    except Exception as e:
        logging.error(f"Error uninstalling service: {e}")
        raise


def _uninstall_linux_service():
    """Uninstall the systemd service on Linux."""
    service_path = f'/etc/systemd/system/{SYSTEMD_SERVICE}.service'
    old_service_path = '/etc/systemd/system/rmm-agent.service'

    # Stop and disable current service
    run_clean_subprocess(['systemctl', 'stop', SYSTEMD_SERVICE], check=False)
    run_clean_subprocess(['systemctl', 'disable', SYSTEMD_SERVICE], check=False)

    # Stop and disable old service
    run_clean_subprocess(['systemctl', 'stop', 'rmm-agent'], check=False)
    run_clean_subprocess(['systemctl', 'disable', 'rmm-agent'], check=False)

    # Remove service files
    for path in [service_path, old_service_path]:
        if os.path.exists(path):
            os.remove(path)
            logging.info(f"Removed systemd service: {path}")

    run_clean_subprocess(['systemctl', 'daemon-reload'])


def _uninstall_macos_service():
    """Uninstall the LaunchDaemon on macOS."""
    plist_path = f'/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist'
    old_plist_path = '/Library/LaunchDaemons/com.rmm.agent.plist'

    # Unload current service
    if os.path.exists(plist_path):
        run_clean_subprocess(['launchctl', 'bootout', f'system/{LAUNCHD_LABEL}'], check=False)
        os.remove(plist_path)
        logging.info(f"Removed LaunchDaemon: {plist_path}")

    # Unload old service
    if os.path.exists(old_plist_path):
        run_clean_subprocess(['launchctl', 'bootout', 'system/com.rmm.agent'], check=False)
        os.remove(old_plist_path)
        logging.info(f"Removed legacy LaunchDaemon: {old_plist_path}")


def _uninstall_windows_service():
    """Uninstall the Windows service."""
    for service_name in [WINDOWS_SERVICE, 'RMM_Agent']:
        run_clean_subprocess(['sc', 'stop', service_name], check=False)
        run_clean_subprocess(['sc', 'delete', service_name], check=False)
        logging.info(f"Removed Windows service: {service_name}")


def run_clean_subprocess(cmd, check=True, **kwargs):
    """
    Run a subprocess with a clean environment.

    Removes LD_LIBRARY_PATH to avoid PyInstaller bundled library conflicts.
    """
    env = os.environ.copy()
    env.pop('LD_LIBRARY_PATH', None)

    try:
        result = subprocess.run(cmd, env=env, check=check, capture_output=True, text=True, **kwargs)
        return result
    except subprocess.CalledProcessError as e:
        if check:
            logging.error(f"Command failed: {' '.join(cmd)}: {e.stderr}")
            raise
        return e
    except Exception as e:
        logging.error(f"Error executing command {' '.join(cmd)}: {e}")
        if check:
            raise
        return None


def get_all_user_homes():
    """Get all user home directories on macOS."""
    users_dir = Path('/Users')
    return [p for p in users_dir.iterdir() if p.is_dir() and not p.name.startswith('.')]


def get_bundle_id(app_path):
    """Extract the bundle identifier from a macOS application."""
    info_plist = app_path / 'Contents' / 'Info.plist'
    if info_plist.exists():
        with open(info_plist, 'rb') as f:
            plist = plistlib.load(f)
            return plist.get('CFBundleIdentifier')
    return None


def find_related_files(bundle_id):
    """Find all files related to a bundle ID on macOS."""
    user_homes = []
    try:
        user_homes = get_all_user_homes()
    except Exception as e:
        logging.warning(f"Failed to list user homes: {e}")

    search_dirs = []
    for home in user_homes:
        search_dirs += [
            home / 'Library' / 'Application Support',
            home / 'Library' / 'Preferences',
            home / 'Library' / 'Caches',
            home / 'Library' / 'Logs',
        ]

    # System-wide directories
    search_dirs += [
        Path('/Library/Application Support'),
        Path('/Library/Preferences'),
        Path('/Library/Caches'),
        Path('/Library/Logs'),
    ]

    found = []
    for directory in search_dirs:
        if directory.exists():
            for item in directory.glob(f'*{bundle_id}*'):
                found.append(item)
    return found


def uninstall_software(package_name, app_path=None):
    """
    Uninstall software from the system.

    Supports macOS applications and Linux packages (apt, dnf, yum, zypper, rpm).
    """
    logging.info(f"Attempting to uninstall software: {package_name}")
    system = platform.system()

    try:
        if system == 'Darwin':
            return _uninstall_macos_app(package_name, app_path)
        elif system == 'Linux':
            return _uninstall_linux_package(package_name)
        else:
            return {"success": False, "error": f"Unsupported OS: {system}"}

    except Exception as e:
        logging.error(f"Error uninstalling software: {e}")
        return {"success": False, "error": str(e)}


def _uninstall_macos_app(package_name, app_path=None):
    """Uninstall a macOS application."""
    # Find the app
    if app_path:
        app_found = Path(app_path)
        if not app_found.exists():
            return {"success": False, "error": f"App path {app_path} not found."}
    else:
        app_paths = [
            Path('/Applications') / f'{package_name}.app',
            Path.home() / 'Applications' / f'{package_name}.app'
        ]
        app_found = None
        for p in app_paths:
            if p.exists():
                app_found = p
                break

        if not app_found:
            return {"success": False, "error": f"App {package_name} not found."}

    logging.info(f"Found app at: {app_found}")

    # Get bundle ID and find related files
    bundle_id = get_bundle_id(app_found)
    logging.info(f"Bundle ID: {bundle_id}")

    # Delete related files
    related_files = find_related_files(bundle_id) if bundle_id else []
    for item in related_files:
        if item.exists():
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
                logging.info(f"Deleted: {item}")
            except Exception as e:
                logging.warning(f"Failed to delete {item}: {e}")

    # Delete the app bundle
    try:
        shutil.rmtree(app_found)
        logging.info(f"Deleted app bundle: {app_found}")
    except Exception as e:
        logging.warning(f"Failed to delete app bundle: {e}")

    # Forget PKG receipts
    if bundle_id:
        result = subprocess.run(['pkgutil', '--pkgs'], capture_output=True, text=True)
        pkgs = result.stdout.strip().split('\n')
        matched_pkgs = [pkg for pkg in pkgs if bundle_id.lower() in pkg.lower()]
        for pkg in matched_pkgs:
            logging.info(f"Forgetting PKG: {pkg}")
            subprocess.run(['pkgutil', '--forget', pkg])

    return {"success": True, "bundle_id": bundle_id, "deleted_files": [str(f) for f in related_files]}


def _uninstall_linux_package(package_name):
    """Uninstall a Linux package using available package managers."""
    errors = []

    # Try apt
    if shutil.which('apt'):
        logging.info(f"Trying apt to uninstall {package_name}...")
        result = run_clean_subprocess(['apt', 'purge', '-y', package_name], check=False)
        if result and result.returncode == 0:
            run_clean_subprocess(['apt', 'clean'], check=False)
            return {"success": True, "method": "apt"}
        errors.append(f"apt: {result.stderr if result else 'failed'}")

    # Try dnf
    if shutil.which('dnf'):
        logging.info(f"Trying dnf to uninstall {package_name}...")
        result = run_clean_subprocess(['dnf', 'remove', '-y', package_name], check=False)
        if result and result.returncode == 0:
            run_clean_subprocess(['dnf', 'clean', 'all'], check=False)
            return {"success": True, "method": "dnf"}
        errors.append(f"dnf: {result.stderr if result else 'failed'}")

    # Try yum
    if shutil.which('yum'):
        logging.info(f"Trying yum to uninstall {package_name}...")
        result = run_clean_subprocess(['yum', '-y', 'remove', package_name], check=False)
        if result and result.returncode == 0:
            run_clean_subprocess(['yum', 'clean', 'all'], check=False)
            return {"success": True, "method": "yum"}
        errors.append(f"yum: {result.stderr if result else 'failed'}")

    # Try zypper
    if shutil.which('zypper'):
        logging.info(f"Trying zypper to uninstall {package_name}...")
        result = run_clean_subprocess(['zypper', '--non-interactive', 'rm', package_name], check=False)
        if result and result.returncode == 0:
            run_clean_subprocess(['zypper', 'clean', '--all'], check=False)
            return {"success": True, "method": "zypper"}
        errors.append(f"zypper: {result.stderr if result else 'failed'}")

    # Try rpm as fallback
    if shutil.which('rpm'):
        logging.info(f"Trying rpm to uninstall {package_name}...")
        result = run_clean_subprocess(['rpm', '-e', package_name], check=False)
        if result and result.returncode == 0:
            return {"success": True, "method": "rpm"}
        errors.append(f"rpm: {result.stderr if result else 'failed'}")

    return {"success": False, "error": f"All methods failed: {' | '.join(errors)}"}
