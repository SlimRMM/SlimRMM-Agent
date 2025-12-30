"""
SlimRMM Agent - Windows Service Wrapper
Copyright (c) 2025 Kiefer Networks

Provides Windows service functionality for the SlimRMM Agent.
"""

import sys
import os
import time
import logging

# Only import Windows-specific modules on Windows
if sys.platform == 'win32':
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager
        WINDOWS_SERVICE_AVAILABLE = True
    except ImportError:
        WINDOWS_SERVICE_AVAILABLE = False
else:
    WINDOWS_SERVICE_AVAILABLE = False


class SlimRMMService:
    """Windows Service wrapper for SlimRMM Agent."""

    _svc_name_ = 'SlimRMMAgent'
    _svc_display_name_ = 'SlimRMM Agent'
    _svc_description_ = 'SlimRMM Remote Monitoring and Management Agent'

    def __init__(self, args=None):
        if WINDOWS_SERVICE_AVAILABLE:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        self.agent = None

    def SvcStop(self):
        """Called when the service is being stopped."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False
        logging.info("Service stop requested")

    def SvcDoRun(self):
        """Called when the service is starting."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        """Main service loop."""
        self.is_running = True
        logging.info("SlimRMM Agent service starting...")

        # Import and run the agent
        try:
            # Add the script directory to path
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)

            # Import the main agent module
            import agent as agent_module

            # Run the agent
            agent_module.main()

        except Exception as e:
            logging.error(f"Service error: {e}")
            servicemanager.LogErrorMsg(f"SlimRMM Agent error: {e}")

        logging.info("SlimRMM Agent service stopped")


def install_service():
    """Install the Windows service."""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("Windows service modules not available")
        return False

    try:
        # Get the path to the executable
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(__file__)

        win32serviceutil.InstallService(
            None,
            SlimRMMService._svc_name_,
            SlimRMMService._svc_display_name_,
            startType=win32service.SERVICE_AUTO_START,
            exeName=exe_path,
            description=SlimRMMService._svc_description_
        )
        print(f"Service '{SlimRMMService._svc_display_name_}' installed successfully")
        return True
    except Exception as e:
        print(f"Failed to install service: {e}")
        return False


def uninstall_service():
    """Uninstall the Windows service."""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("Windows service modules not available")
        return False

    try:
        win32serviceutil.RemoveService(SlimRMMService._svc_name_)
        print(f"Service '{SlimRMMService._svc_display_name_}' removed successfully")
        return True
    except Exception as e:
        print(f"Failed to remove service: {e}")
        return False


def start_service():
    """Start the Windows service."""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("Windows service modules not available")
        return False

    try:
        win32serviceutil.StartService(SlimRMMService._svc_name_)
        print(f"Service '{SlimRMMService._svc_display_name_}' started")
        return True
    except Exception as e:
        print(f"Failed to start service: {e}")
        return False


def stop_service():
    """Stop the Windows service."""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("Windows service modules not available")
        return False

    try:
        win32serviceutil.StopService(SlimRMMService._svc_name_)
        print(f"Service '{SlimRMMService._svc_display_name_}' stopped")
        return True
    except Exception as e:
        print(f"Failed to stop service: {e}")
        return False


def run_as_service():
    """Run as a Windows service."""
    if not WINDOWS_SERVICE_AVAILABLE:
        print("Windows service modules not available. Running in console mode.")
        return False

    if len(sys.argv) == 1:
        # Called without arguments - run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SlimRMMService)
        servicemanager.StartServiceCtrlDispatcher()
        return True
    else:
        # Handle command line arguments
        win32serviceutil.HandleCommandLine(SlimRMMService)
        return True


if __name__ == '__main__':
    if WINDOWS_SERVICE_AVAILABLE:
        run_as_service()
    else:
        print("This module requires Windows and pywin32")
