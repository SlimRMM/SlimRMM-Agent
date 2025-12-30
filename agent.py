"""
SlimRMM Agent
Copyright (c) 2025 Kiefer Networks

A lightweight Remote Monitoring and Management agent.
"""

import sys
import socket
import requests
import json
import platform
import subprocess
import shutil
import logging
import os
import pwd
import re
import urllib.request
import tempfile
import tarfile
from service_utils import get_install_dir, is_admin, uninstall_service, CONFIG_FILENAME, LAUNCHD_LABEL, SYSTEMD_SERVICE

# Agent version
AGENT_VERSION = "1.0.0"


def setup_logging(target_dir):
    log_dir = os.path.join(target_dir, 'log')
    log_filename = os.path.join(log_dir, 'agent.log')

    # Erstelle Log-Verzeichnis mit korrekten Berechtigungen
    try:
        os.makedirs(log_dir, mode=0o755, exist_ok=True)
        logging.info(f"Created log directory: {log_dir}")
    except Exception as e:
        print(f"❌ Failed to create log directory {log_dir}: {e}", file=sys.stderr)
        raise

    # Konfiguriere Logging
    try:
        # Erstelle Datei mit Schreibrechten
        with open(log_filename, 'a') as f:
            os.chmod(log_filename, 0o644)
        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info("Logging initialized successfully.")
    except Exception as e:
        print(f"❌ Failed to initialize logging to {log_filename}: {e}", file=sys.stderr)
        # Fallback auf stderr
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.warning("Logging initialized to stderr due to file error.")


def find_display_session():
    """Finde die DISPLAY-Variable einer laufenden X-Session."""
    try:
        output = subprocess.check_output(["w", "-h"], text=True)
        for line in output.splitlines():
            if ":0" in line or ":0.0" in line:
                user = line.split()[0]
                return ":0", pwd.getpwnam(user).pw_dir + "/.Xauthority"
    except Exception as e:
        logging.warning(f"Could not find DISPLAY via w: {e}")

    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            cmdline_path = f"/proc/{pid}/cmdline"
            if os.path.exists(cmdline_path):
                with open(cmdline_path, "rb") as f:
                    cmdline = f.read().decode(errors="ignore").split("\0")
                if any("Xorg" in arg for arg in cmdline):
                    for arg in cmdline:
                        if arg.startswith(":"):
                            display = arg
                            stat = os.stat(f"/proc/{pid}")
                            user = pwd.getpwuid(stat.st_uid).pw_name
                            return display, pwd.getpwnam(user).pw_dir + "/.Xauthority"
    except Exception as e:
        logging.warning(f"Could not find DISPLAY via /proc: {e}")

    return None, None


def setup_graphical_environment():
    """Richte die grafische Umgebung für Root ein."""
    system = platform.system()
    if system != "Linux":
        logging.info("macOS graphical environment: No DISPLAY setup needed")
        return

    if os.environ.get("DISPLAY"):
        logging.info(f"DISPLAY already set: {os.environ['DISPLAY']}")
        return

    display, xauthority = find_display_session()
    if display and xauthority and os.path.exists(xauthority):
        try:
            os.environ["DISPLAY"] = display
            os.environ["XAUTHORITY"] = xauthority
            logging.info(f"Set DISPLAY={display} and XAUTHORITY={xauthority}")
            subprocess.run(["xhost", "+SI:localuser:root"], check=True, capture_output=True)
            logging.info("Granted Root access to X session via xhost")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to configure X session with xhost: {e.stderr.decode().strip()}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error configuring X session: {e}")
            raise
    else:
        try:
            subprocess.run(["Xvfb", ":0", "-screen", "0", "1920x1080x24"], check=True)
            os.environ["DISPLAY"] = ":0"
            logging.info("Started Xvfb for headless display")
        except Exception as e:
            logging.error(f"Failed to start Xvfb: {e}")
            raise


def install_osquery():
    from osquery_handler import find_osquery_binary
    system = platform.system()
    osquery_path = find_osquery_binary()
    if osquery_path:
        try:
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = ""
            version_output = subprocess.check_output([osquery_path, "--version"], env=env).decode()
            logging.info(f"osqueryi already installed at {osquery_path}. Version: {version_output.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error checking osqueryi version: {e}")
            if os.path.exists(osquery_path):
                try:
                    version_output = subprocess.check_output([osquery_path, "--version"]).decode()
                    logging.info(f"osqueryi found at {osquery_path}. Version: {version_output.strip()}")
                    return True
                except Exception as e:
                    logging.error(f"Alternative version check failed: {e}")
            logging.warning("Version check failed, attempting to reinstall osquery")
        except Exception as e:
            logging.error(f"Unexpected error checking osqueryi version: {e}")

    logging.info("Installing osquery...")
    try:
        if system == "Linux":
            distro = subprocess.check_output(["cat", "/etc/os-release"]).decode().lower()
            if "arch" in distro:
                try:
                    subprocess.run(["pacman", "-Syu", "--noconfirm"], check=True, capture_output=True)
                    subprocess.run(["pacman", "-S", "--noconfirm", "osquery"], check=True, capture_output=True)
                    logging.info("osquery installed via pacman")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to install osquery via pacman: {e.stderr.decode().strip()}")
            elif "ubuntu" in distro or "debian" in distro:
                try:
                    subprocess.run(["apt-get", "update"], check=True, capture_output=True)
                    subprocess.run(["apt-get", "install", "-y", "osquery"], check=True, capture_output=True)
                    logging.info("osquery installed via apt-get")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to install osquery via apt-get: {e.stderr.decode().strip()}")
            elif "centos" in distro or "rhel" in distro or "fedora" in distro:
                try:
                    subprocess.run(["yum", "install", "-y", "osquery"], check=True, capture_output=True)
                    logging.info("osquery installed via yum")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to install osquery via yum: {e.stderr.decode().strip()}")
            osquery_url = "https://github.com/osquery/osquery/releases/download/5.20.0/osquery-5.20.0_1.linux_x86_64.tar.gz"
            temp_dir = tempfile.gettempdir()
            tar_path = os.path.join(temp_dir, "osquery.tar.gz")
            logging.info(f"Downloading osquery from {osquery_url}")
            urllib.request.urlretrieve(osquery_url, tar_path)
            install_dir = "/usr/local/osquery"
            os.makedirs(install_dir, exist_ok=True)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=install_dir)
            osqueryi_path = os.path.join(install_dir, "osquery/osqueryi")
            if os.path.exists(osqueryi_path):
                shutil.copy(osqueryi_path, "/usr/local/bin/osqueryi")
                os.chmod("/usr/local/bin/osqueryi", 0o755)
                logging.info("osquery installed from tar.gz")
            else:
                logging.error("osqueryi binary not found in tar.gz")
                return False
            os.remove(tar_path)
        elif system == "Darwin":
            osquery_url = "https://github.com/osquery/osquery/releases/download/5.20.0/osquery-5.20.0.pkg"
            temp_dir = tempfile.gettempdir()
            pkg_path = os.path.join(temp_dir, "osquery.pkg")
            logging.info(f"Downloading osquery from {osquery_url}")
            urllib.request.urlretrieve(osquery_url, pkg_path)
            subprocess.run(["installer", "-pkg", pkg_path, "-target", "/"], check=True, capture_output=True)
            logging.info("osquery installed via pkg")
            os.remove(pkg_path)
        elif system == "Windows":
            osquery_url = "https://github.com/osquery/osquery/releases/download/5.16.0/osquery-5.16.0_1.windows.msi"
            temp_dir = tempfile.gettempdir()
            msi_path = os.path.join(temp_dir, "osquery.msi")
            logging.info(f"Downloading osquery from {osquery_url}")
            urllib.request.urlretrieve(osquery_url, msi_path)
            subprocess.run(["msiexec", "/i", msi_path, "/quiet", "/norestart"], check=True, capture_output=True)
            logging.info("osquery installed via msi")
            os.remove(msi_path)
        osquery_path = find_osquery_binary()
        if osquery_path:
            try:
                env = os.environ.copy()
                env["LD_LIBRARY_PATH"] = ""
                version_output = subprocess.check_output([osquery_path, "--version"], env=env).decode()
                logging.info(f"osqueryi successfully installed. Version: {version_output.strip()}")
                return True
            except Exception as e:
                logging.error(f"Error verifying osqueryi version after installation: {e}")
                if os.path.exists(osquery_path):
                    logging.info(f"osqueryi found at {osquery_path}, assuming installation successful")
                    return True
        logging.error("osqueryi installation failed: Binary not found after installation attempt")
        return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing osquery: {e.stderr.decode().strip()}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error installing osquery: {e}")
        return False


def copy_agent_to_target(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    if getattr(sys, 'frozen', False):
        source_dir = os.path.dirname(sys.executable)
        logging.info(f"Copying all files from {source_dir} to {target_dir}")
        for item in os.listdir(source_dir):
            s = os.path.join(source_dir, item)
            d = os.path.join(target_dir, item)
            try:
                if os.path.isdir(s):
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
            except Exception as e:
                logging.error(f"Error copying {s} to {d}: {e}")
                raise
    else:
        source_file = os.path.abspath(__file__)
        try:
            shutil.copy2(source_file, os.path.join(target_dir, 'agent.py'))
            logging.info(f"Copied agent.py to {target_dir}")
        except Exception as e:
            logging.error(f"Error copying agent.py to {target_dir}: {e}")
            raise


def register_agent(installation_key, server_url):
    system = platform.system().lower()
    arch = platform.machine().lower()
    hostname = socket.gethostname()
    data = {
        "installation_key": installation_key,
        "os": system,
        "arch": arch,
        "hostname": hostname,
        "agent_version": AGENT_VERSION
    }
    try:
        logging.info(f"Registering agent with server: {server_url}")
        response = requests.post(f"{server_url}/api/v1/agents/register", json=data, timeout=10)
        response.raise_for_status()
        result = response.json()
        uuid_val = result.get("uuid")
        api_key = result.get("api_key")
        if not uuid_val:
            raise Exception("No UUID returned from server")
        logging.info(f"Successfully registered. UUID: {uuid_val}")
        return uuid_val, api_key
    except requests.RequestException as e:
        logging.error(f"Error registering agent with server {server_url}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logging.error(f"Response: {e.response.text}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error registering agent: {e}")
        raise


def create_symlink_or_shortcut(target_dir):
    system = platform.system()
    if system in ['Linux', 'Darwin']:
        target_bin = '/usr/local/bin/agent'
        if os.path.exists(target_bin):
            try:
                os.remove(target_bin)
                logging.info(f"Removed existing symlink at {target_bin}")
            except Exception as e:
                logging.error(f"Error removing existing symlink {target_bin}: {e}")
                raise
        agent_binary = os.path.join(target_dir, 'agent') if getattr(sys, 'frozen', False) else os.path.join(target_dir,
                                                                                                            'agent.py')
        try:
            os.symlink(agent_binary, target_bin)
            logging.info(f"Created symlink at {target_bin} -> {agent_binary}")
        except Exception as e:
            logging.error(f"Error creating symlink {target_bin} -> {agent_binary}: {e}")
            raise
    elif system == 'Windows':
        logging.info("Windows shortcut creation not implemented")
        pass


def install_service(installation_key, server_url):
    if not is_admin():
        logging.error("Installation requires administrator/root privileges")
        print("❌ You need to run this script as administrator/root.")
        sys.exit(1)

    system = platform.system()
    target_dir = get_install_dir()
    os.makedirs(target_dir, exist_ok=True)
    setup_logging(target_dir)

    logging.info("Starting osquery installation check")
    if not install_osquery():
        logging.error("osquery installation failed")
        print("❌ Failed to install osquery. Exiting.")
        sys.exit(1)

    logging.info("Copying agent files to target directory")
    copy_agent_to_target(target_dir)
    create_symlink_or_shortcut(target_dir)

    python_executable = sys.executable
    if system in ['Linux', 'Darwin']:
        script_path = os.path.join(target_dir, 'agent')
    else:
        script_path = os.path.join(target_dir, 'agent.exe') if getattr(sys, 'frozen', False) else os.path.join(
            target_dir, 'agent.py')

    logging.info("Registering agent with server")
    agent_uuid, api_key = register_agent(installation_key, server_url)
    config = {
        "server": server_url,
        "api_key": api_key,
        "uuid": agent_uuid
    }
    config_path = os.path.join(target_dir, CONFIG_FILENAME)
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        logging.info(f"Saved config to {config_path}")
    except Exception as e:
        logging.error(f"Error saving config to {config_path}: {e}")
        raise

    log_dir = os.path.join(target_dir, 'log')
    logging.info(f"Installing service on {system}")
    try:
        if system == 'Linux':
            display, xauthority = find_display_session()
            if not display:
                display = ":0"
                xauthority = "/home/user/.Xauthority"  # Ersetze 'user' mit dem tatsächlichen Benutzer
            service_content = f"""
[Unit]
Description=SlimRMM Agent
After=network.target

[Service]
ExecStart={script_path}
Restart=always
User=root
WorkingDirectory={target_dir}
StandardOutput=file:{log_dir}/stdout.log
StandardError=file:{log_dir}/stderr.log
Environment=DISPLAY={display}
Environment=XAUTHORITY={xauthority}
Environment=PATH={os.environ["PATH"]}

[Install]
WantedBy=multi-user.target
""".strip()
            service_path = f'/etc/systemd/system/{SYSTEMD_SERVICE}.service'
            with open(service_path, 'w') as f:
                f.write(service_content)
            logging.info(f"Created systemd service at {service_path}")
            run_clean_subprocess(['systemctl', 'daemon-reload'])
            run_clean_subprocess(['systemctl', 'enable', SYSTEMD_SERVICE])
            run_clean_subprocess(['systemctl', 'start', SYSTEMD_SERVICE])
            logging.info("Enabled and started systemd service")
        elif system == 'Darwin':
            plist_content = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{python_executable}</string>
      <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{target_dir}</string>
    <key>StandardOutPath</key>
    <string>{os.path.join(log_dir, 'stdout.log')}</string>
    <key>StandardErrorPath</key>
    <string>{os.path.join(log_dir, 'stderr.log')}</string>
    <key>EnvironmentVariables</key>
    <dict>
      <key>PATH</key>
      <string>{os.environ["PATH"]}</string>
    </dict>
  </dict>
</plist>
""".strip()
            plist_path = f'/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist'
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            logging.info(f"Created LaunchDaemon at {plist_path}")
            run_clean_subprocess(['launchctl', 'bootstrap', 'system', plist_path])
            logging.info("Loaded LaunchDaemon (macOS)")

            # Request Full Disk Access permission
            request_full_disk_access()
        elif system == 'Windows':
            service_name = "RMM_Agent"
            bin_path = f'"{python_executable}" "{script_path}"'
            run_clean_subprocess(['sc', 'create', service_name, 'binPath=', bin_path])
            logging.info(f"Created Windows service '{service_name}'")
    except Exception as e:
        logging.error(f"Error installing service: {e}")
        raise


def run_clean_subprocess(cmd, **kwargs):
    env = os.environ.copy()
    env.pop('LD_LIBRARY_PATH', None)
    try:
        result = subprocess.run(cmd, env=env, check=True, **kwargs)
        logging.info(f"Successfully executed command: {' '.join(cmd)}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command {' '.join(cmd)}: {e.stderr.decode().strip() if e.stderr else e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error executing command {' '.join(cmd)}: {e}")
        raise


def request_full_disk_access():
    """Request Full Disk Access and Screen Recording permissions on macOS."""
    target_dir = get_install_dir()
    agent_path = os.path.join(target_dir, 'slimrmm-agent')

    print("\n" + "=" * 60)
    print("  SlimRMM Agent - Permissions Required")
    print("=" * 60)
    print(f"""
The SlimRMM Agent requires the following permissions:

1. FULL DISK ACCESS (Required)
   - Enables file management and system monitoring

2. SCREEN RECORDING (Optional)
   - Enables remote desktop functionality

Please follow these steps:

1. System Settings will now open
2. Go to Privacy & Security
3. Add the following to Full Disk Access:
   {agent_path}
4. (Optional) Add to Screen Recording for remote desktop

5. Restart the agent with:
   sudo launchctl kickstart -k system/{LAUNCHD_LABEL}
""")
    print("=" * 60)

    # Open System Preferences to Full Disk Access
    try:
        subprocess.run([
            'open',
            'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'
        ], check=False)
        logging.info("Opened System Preferences for Full Disk Access")
    except Exception as e:
        logging.warning(f"Could not open System Preferences: {e}")
        print("\nIf System Preferences did not open:")
        print("Go to: System Preferences → Privacy & Security → Full Disk Access")

    # Wait for user confirmation
    try:
        input("\nPress ENTER when you have granted the permissions...")
    except EOFError:
        # Non-interactive mode, just continue
        pass

    print("\nInstallation complete. The agent is now running.")


if __name__ == '__main__':
    args = sys.argv
    if '--install' in args:
        try:
            # Support both --installation-key and --api-key for backwards compatibility
            if '--installation-key' in args:
                key_idx = args.index('--installation-key') + 1
            elif '--api-key' in args:
                key_idx = args.index('--api-key') + 1
            else:
                raise ValueError("Missing installation key argument")
            server_idx = args.index('--server') + 1
            installation_key = args[key_idx]
            server_url = args[server_idx]
        except (ValueError, IndexError):
            print("SlimRMM Agent - Installation")
            print("")
            print("Usage: slimrmm-agent --install --installation-key <key> --server <url>")
            sys.exit(1)
        print("SlimRMM Agent - Installing...")
        logging.info("Starting agent installation")
        install_service(installation_key, server_url)
        print("Installation completed.")
        logging.info("Agent installation completed")
    elif '--uninstall' in args:
        print("SlimRMM Agent - Uninstalling...")
        logging.info("Starting agent uninstallation")
        uninstall_service()
        print("Uninstallation completed.")
        logging.info("Agent uninstallation completed")
    else:
        target_dir = get_install_dir()
        setup_logging(target_dir)
        logging.info("Starting agent WebSocket")
        from ws_handler import start_websocket

        start_websocket()