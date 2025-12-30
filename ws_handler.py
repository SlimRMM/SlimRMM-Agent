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
import tempfile
from pathlib import Path
from typing import Set, Dict, Any, Union

from osquery_handler import run_osquery_query
from service_utils import uninstall_service, is_admin, uninstall_software
from config import load_config

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

    ws_url = f"{server.replace('http', 'ws')}/api/v1/ws/agent?uuid={agent_uuid}"
    logging.info(f"Connecting to WebSocket: {ws_url}")

    def send_heartbeat(ws, interval=30):
        while True:
            try:
                # Include system stats with heartbeat
                stats = get_system_stats()
                heartbeat_msg = json.dumps({
                    "action": "heartbeat",
                    "stats": stats
                })
                ws.send(heartbeat_msg)
                logging.info(f"❤️ Sent heartbeat with stats: CPU={stats.get('cpu_percent', 0):.1f}%, Mem={stats.get('memory_percent', 0):.1f}%")
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
                request_id = data.get('request_id')  # Important: Pass back the request_id
                result = run_osquery_query(query)
                response = {
                    "status": "success",
                    "action": "run_osquery",
                    "scan_type": data.get('scan_type'),
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
            ws.run_forever(ping_interval=30, ping_timeout=20)
        except Exception as e:
            logging.error(f"WebSocket error: {e}")
        logging.info("🔄 Reconnecting in 5 seconds...")
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

def start_terminal(ws):
    global terminal_process, terminal_running, terminal_thread, master_fd
    if terminal_running:
        logging.warning("Terminal already running.")
        return
    system = platform.system()
    if system in ['Linux', 'Darwin']:
        import pty
        master_fd, slave_fd = pty.openpty()
        shell = os.environ.get('SHELL', '/bin/zsh')
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
    """
    from osquery_handler import run_osquery_query

    try:
        # Get total physical memory and CPU cores from system_info
        sys_info = run_osquery_query("SELECT physical_memory, cpu_logical_cores FROM system_info;")

        memory_total = 0
        cpu_cores = 1

        if sys_info and not isinstance(sys_info, dict) and len(sys_info) > 0:
            memory_total = int(sys_info[0].get("physical_memory", 0))
            cpu_cores = int(sys_info[0].get("cpu_logical_cores", 1)) or 1

        # Get memory usage from virtual_memory_info (values in pages, page_size = 4096 bytes)
        memory_used = 0
        memory_percent = 0.0
        page_size = 4096  # macOS/Linux page size

        vm_info = run_osquery_query("SELECT free, active, inactive, wired FROM virtual_memory_info;")
        if vm_info and not isinstance(vm_info, dict) and len(vm_info) > 0:
            row = vm_info[0]
            # Used memory = active + wired pages
            active_pages = int(row.get("active", 0))
            wired_pages = int(row.get("wired", 0))
            memory_used = (active_pages + wired_pages) * page_size
            if memory_total > 0:
                memory_percent = (memory_used / memory_total) * 100.0

        # Get CPU load average (1 minute) as percentage approximation
        cpu_percent = 0.0
        load_result = run_osquery_query("SELECT average FROM load_average WHERE period = '1m';")

        if load_result and not isinstance(load_result, dict) and len(load_result) > 0:
            load_avg = float(load_result[0].get("average", 0))
            # Convert load average to percentage (load / cores * 100)
            cpu_percent = min((load_avg / cpu_cores) * 100.0, 100.0)

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
    The agent service will be restarted after the update.
    """
    import urllib.request
    import ssl

    system = platform.system()
    config = load_config()

    if not server_url:
        server_url = config.get('server', '')

    if not server_url:
        return {"success": False, "error": "No server URL configured"}

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
            agent_path = Path('/var/lib/rmm/rmm-agent')
        elif system == 'Linux':
            agent_path = Path('/var/lib/rmm/rmm-agent')

        if not agent_path.exists():
            # Try to find agent in current directory
            agent_path = Path(sys.executable).parent / 'rmm-agent'

        # Create backup
        backup_path = agent_path.with_suffix('.backup')
        if agent_path.exists():
            shutil.copy2(agent_path, backup_path)
            logging.info(f"Created backup at {backup_path}")

        # Download new agent binary
        temp_path = Path(tempfile.gettempdir()) / 'rmm-agent-new'

        logging.info(f"Downloading agent from {download_url}")

        # Create SSL context (allow self-signed for development)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

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