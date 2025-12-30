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
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        decoded = result.decode().strip()

        # Handle empty results
        if not decoded:
            return []

        return json.loads(decoded)

    except subprocess.CalledProcessError as e:
        error_output = e.output.decode().strip() if e.output else "Unknown error"
        logging.error(f"Osquery execution failed: {error_output}")
        return {"error": error_output}
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse osquery JSON output: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error running osquery: {e}")
        return {"error": str(e)}
