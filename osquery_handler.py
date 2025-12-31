import os
import shutil
import subprocess
import logging
import json
import platform

def find_osquery_binary():
    """
    Sucht nach 'osqueryi' oder 'osqueryi.exe' im Pfad, je nach Plattform.
    Gibt den vollen Pfad zurück oder None.
    """
    binary_name = 'osqueryi'
    system = platform.system()
    if system == 'Windows':
        binary_name += '.exe'

    # Check if already in PATH
    binary_path = shutil.which(binary_name)
    if binary_path:
        return binary_path

    # Extra Check: Common install locations
    common_paths = []
    if system == 'Darwin':
        common_paths = ['/usr/local/bin/osqueryi', '/opt/homebrew/bin/osqueryi']
    elif system == 'Linux':
        common_paths = ['/usr/local/bin/osqueryi', '/usr/bin/osqueryi']
    elif system == 'Windows':
        program_files = os.environ.get('ProgramFiles', r'C:\Program Files')
        common_paths = [os.path.join(program_files, 'osquery', 'osqueryi.exe')]

    for path in common_paths:
        if os.path.exists(path):
            return path

    return None

def run_osquery_query(query):
    try:
        osquery_binary = find_osquery_binary()
        if not osquery_binary:
            error_msg = "osqueryi binary not found on system. Please ensure it is installed and in PATH."
            logging.error(error_msg)
            return {"error": error_msg}

        cmd = [osquery_binary, '--json', query]
        logging.debug(f"Executing osquery: {' '.join(cmd)}")

        # Capture both stdout and stderr for better error diagnosis
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            # Log the actual error from stderr
            stderr_msg = result.stderr.strip() if result.stderr else "No error message"
            error_msg = f"Osquery execution failed (exit code {result.returncode}): {stderr_msg}"
            logging.error(error_msg)
            # Log the query that failed for debugging
            logging.debug(f"Failed query: {query[:200]}...")  # Log first 200 chars
            return {"error": error_msg}

        decoded = result.stdout.strip()

        # Handle empty results
        if not decoded:
            return []

        return json.loads(decoded)

    except subprocess.TimeoutExpired:
        error_msg = "Osquery execution timed out after 60 seconds"
        logging.error(error_msg)
        return {"error": error_msg}
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse osquery JSON output: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error running osquery: {e}")
        return {"error": str(e)}
