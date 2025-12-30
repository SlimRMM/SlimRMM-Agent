"""
Remote Desktop Module for RMM Agent.

Provides WebRTC-based screen sharing and remote control functionality.
Uses mss for screen capture, aiortc for WebRTC, and pynput for input control.
"""

import asyncio
import json
import logging
import platform
import threading
import time
from fractions import Fraction
from typing import Dict, Any, Optional, List, Callable

try:
    import mss
    import mss.tools
    MSS_AVAILABLE = True
except ImportError:
    MSS_AVAILABLE = False
    logging.warning("mss not available - screen capture disabled")

try:
    from aiortc import (
        RTCPeerConnection,
        RTCSessionDescription,
        RTCIceCandidate,
        RTCConfiguration,
        RTCIceServer,
    )
    from aiortc.sdp import candidate_from_sdp
    from aiortc.contrib.media import MediaStreamTrack
    from av import VideoFrame
    import numpy as np
    AIORTC_AVAILABLE = True
except ImportError:
    AIORTC_AVAILABLE = False
    logging.warning("aiortc not available - WebRTC disabled")

try:
    from pynput.mouse import Controller as MouseController, Button
    from pynput.keyboard import Controller as KeyboardController, Key
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    logging.warning("pynput not available - remote control disabled")

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False
    logging.warning("pyperclip not available - clipboard sync disabled")


# WebRTC Configuration - Public STUN servers
def get_rtc_configuration():
    """Create RTCConfiguration with STUN servers."""
    if not AIORTC_AVAILABLE:
        return None
    return RTCConfiguration(
        iceServers=[
            RTCIceServer(urls=["stun:stun.l.google.com:19302"]),
            RTCIceServer(urls=["stun:stun1.l.google.com:19302"]),
            RTCIceServer(urls=["stun:stun2.l.google.com:19302"]),
        ]
    )

# Global state
active_sessions: Dict[str, 'RemoteDesktopSession'] = {}


class ScreenCaptureTrack(MediaStreamTrack if AIORTC_AVAILABLE else object):
    """
    Video track that captures the screen and streams it via WebRTC.
    """
    kind = "video"

    def __init__(self, monitor_id: int = 1, fps: int = 30, quality: str = "balanced"):
        if AIORTC_AVAILABLE:
            super().__init__()

        self.monitor_id = monitor_id
        self.fps = fps
        self.quality = quality
        self._running = True
        self._frame_count = 0
        self._start_time = time.time()

        # Quality presets
        self._quality_settings = {
            "low": {"scale": 0.5, "fps": 15},
            "balanced": {"scale": 0.75, "fps": 30},
            "high": {"scale": 1.0, "fps": 60},
        }

        self._sct = mss.mss() if MSS_AVAILABLE else None

    def set_quality(self, quality: str):
        """Change quality settings."""
        if quality in self._quality_settings:
            self.quality = quality
            settings = self._quality_settings[quality]
            self.fps = settings["fps"]
            logging.info(f"Quality set to {quality}: scale={settings['scale']}, fps={self.fps}")

    def set_monitor(self, monitor_id: int):
        """Switch to a different monitor."""
        if self._sct and 0 <= monitor_id < len(self._sct.monitors):
            self.monitor_id = monitor_id
            logging.info(f"Switched to monitor {monitor_id}")

    async def recv(self):
        """Capture and return the next video frame."""
        if not self._running or not self._sct:
            return None

        # Calculate frame timing
        pts = self._frame_count
        self._frame_count += 1

        # Wait for next frame timing
        elapsed = time.time() - self._start_time
        expected = self._frame_count / self.fps
        if expected > elapsed:
            await asyncio.sleep(expected - elapsed)

        try:
            # Capture screen
            monitor = self._sct.monitors[self.monitor_id]
            screenshot = self._sct.grab(monitor)

            # Convert to numpy array
            img = np.array(screenshot)

            # BGRA to RGB conversion
            img = img[:, :, :3]  # Remove alpha channel
            img = img[:, :, ::-1]  # BGR to RGB

            # Apply quality scaling
            scale = self._quality_settings[self.quality]["scale"]
            if scale < 1.0:
                new_height = int(img.shape[0] * scale)
                new_width = int(img.shape[1] * scale)
                # Simple resize using numpy (or use cv2 if available)
                img = img[::int(1/scale), ::int(1/scale)]

            # Create VideoFrame
            frame = VideoFrame.from_ndarray(img, format="rgb24")
            frame.pts = pts
            frame.time_base = Fraction(1, self.fps)

            return frame

        except Exception as e:
            logging.error(f"Screen capture error: {e}")
            return None

    def stop(self):
        """Stop the capture track."""
        self._running = False
        if self._sct:
            self._sct.close()


class RemoteDesktopSession:
    """
    Manages a single remote desktop session.
    """

    def __init__(self, session_id: str, send_callback: Callable):
        self.session_id = session_id
        self.send_callback = send_callback
        self.pc: Optional[RTCPeerConnection] = None
        self.video_track: Optional[ScreenCaptureTrack] = None
        self.data_channel = None
        self._running = False
        self._selected_monitor = 1
        self._quality = "balanced"

        # Input controllers
        self._mouse = MouseController() if PYNPUT_AVAILABLE else None
        self._keyboard = KeyboardController() if PYNPUT_AVAILABLE else None

        # Monitor info cache
        self._monitors = []
        self._update_monitors()

    def _update_monitors(self):
        """Update the list of available monitors."""
        if MSS_AVAILABLE:
            with mss.mss() as sct:
                self._monitors = []
                for i, mon in enumerate(sct.monitors):
                    if i == 0:  # Skip "all monitors" entry
                        continue
                    self._monitors.append({
                        "id": i,
                        "left": mon["left"],
                        "top": mon["top"],
                        "width": mon["width"],
                        "height": mon["height"],
                        "name": f"Monitor {i}",
                    })

    def get_monitors(self) -> List[Dict]:
        """Return list of available monitors."""
        self._update_monitors()
        return self._monitors

    async def start(self) -> Dict[str, Any]:
        """
        Start the remote desktop session and create WebRTC offer.
        """
        if not AIORTC_AVAILABLE:
            return {"success": False, "error": "WebRTC (aiortc) not available"}

        if not MSS_AVAILABLE:
            return {"success": False, "error": "Screen capture (mss) not available"}

        try:
            # Create peer connection with STUN servers
            self.pc = RTCPeerConnection(configuration=get_rtc_configuration())

            # Handle ICE candidates
            @self.pc.on("icecandidate")
            async def on_icecandidate(candidate):
                if candidate:
                    await self._send_message({
                        "action": "ice_candidate",
                        "session_id": self.session_id,
                        "candidate": {
                            "candidate": candidate.candidate,
                            "sdpMid": candidate.sdpMid,
                            "sdpMLineIndex": candidate.sdpMLineIndex,
                        }
                    })

            # Handle connection state changes
            @self.pc.on("connectionstatechange")
            async def on_connectionstatechange():
                logging.info(f"Connection state: {self.pc.connectionState}")
                if self.pc.connectionState == "failed":
                    await self.stop()

            # Create and add video track
            self.video_track = ScreenCaptureTrack(
                monitor_id=self._selected_monitor,
                quality=self._quality
            )
            self.pc.addTrack(self.video_track)

            # Create data channel for input events
            self.data_channel = self.pc.createDataChannel("input", ordered=True)

            @self.data_channel.on("message")
            def on_message(message):
                self._handle_input(json.loads(message))

            # Create offer
            offer = await self.pc.createOffer()
            await self.pc.setLocalDescription(offer)

            self._running = True

            logging.info(f"Remote desktop session {self.session_id} started")

            return {
                "success": True,
                "offer": {
                    "type": offer.type,
                    "sdp": offer.sdp,
                },
                "monitors": self.get_monitors(),
            }

        except Exception as e:
            logging.error(f"Failed to start remote desktop: {e}")
            return {"success": False, "error": str(e)}

    async def handle_answer(self, answer: Dict) -> Dict[str, Any]:
        """Handle WebRTC answer from the frontend."""
        try:
            await self.pc.setRemoteDescription(
                RTCSessionDescription(sdp=answer["sdp"], type=answer["type"])
            )
            return {"success": True}
        except Exception as e:
            logging.error(f"Failed to handle answer: {e}")
            return {"success": False, "error": str(e)}

    async def handle_ice_candidate(self, candidate: Dict) -> Dict[str, Any]:
        """Add ICE candidate from the frontend."""
        try:
            candidate_str = candidate.get("candidate", "")
            if not candidate_str:
                return {"success": True}  # Empty candidate signals end of candidates

            # Parse the candidate string using aiortc's helper
            ice_candidate = candidate_from_sdp(candidate_str)
            ice_candidate.sdpMid = candidate.get("sdpMid")
            ice_candidate.sdpMLineIndex = candidate.get("sdpMLineIndex")

            await self.pc.addIceCandidate(ice_candidate)
            return {"success": True}
        except Exception as e:
            logging.error(f"Failed to add ICE candidate: {e}")
            return {"success": False, "error": str(e)}

    def _handle_input(self, data: Dict):
        """Handle input events from the data channel."""
        event_type = data.get("type")

        if event_type == "mouse":
            self._handle_mouse(data)
        elif event_type == "keyboard":
            self._handle_keyboard(data)
        elif event_type == "clipboard":
            self._handle_clipboard(data)
        elif event_type == "quality":
            self._set_quality(data.get("quality", "balanced"))
        elif event_type == "monitor":
            self._set_monitor(data.get("monitor_id", 1))

    def _handle_mouse(self, data: Dict):
        """Handle mouse events."""
        if not self._mouse:
            return

        action = data.get("action")
        x = data.get("x", 0)
        y = data.get("y", 0)

        # Get monitor offset
        monitor = self._monitors[self._selected_monitor - 1] if self._monitors else {}
        offset_x = monitor.get("left", 0)
        offset_y = monitor.get("top", 0)

        # Adjust coordinates
        abs_x = offset_x + x
        abs_y = offset_y + y

        try:
            if action == "move":
                self._mouse.position = (abs_x, abs_y)
            elif action == "click":
                button = Button.left if data.get("button") == "left" else Button.right
                self._mouse.position = (abs_x, abs_y)
                self._mouse.click(button)
            elif action == "dblclick":
                button = Button.left if data.get("button") == "left" else Button.right
                self._mouse.position = (abs_x, abs_y)
                self._mouse.click(button, 2)
            elif action == "down":
                button = Button.left if data.get("button") == "left" else Button.right
                self._mouse.position = (abs_x, abs_y)
                self._mouse.press(button)
            elif action == "up":
                button = Button.left if data.get("button") == "left" else Button.right
                self._mouse.release(button)
            elif action == "scroll":
                delta = data.get("delta", 0)
                self._mouse.scroll(0, delta)
        except Exception as e:
            logging.error(f"Mouse event error: {e}")

    def _handle_keyboard(self, data: Dict):
        """Handle keyboard events."""
        if not self._keyboard:
            return

        action = data.get("action")
        key = data.get("key")

        # Map special keys
        special_keys = {
            "Enter": Key.enter,
            "Escape": Key.esc,
            "Backspace": Key.backspace,
            "Tab": Key.tab,
            "Space": Key.space,
            "ArrowUp": Key.up,
            "ArrowDown": Key.down,
            "ArrowLeft": Key.left,
            "ArrowRight": Key.right,
            "Control": Key.ctrl,
            "Alt": Key.alt,
            "Shift": Key.shift,
            "Meta": Key.cmd if platform.system() == "Darwin" else Key.cmd,
            "Delete": Key.delete,
            "Home": Key.home,
            "End": Key.end,
            "PageUp": Key.page_up,
            "PageDown": Key.page_down,
            "F1": Key.f1, "F2": Key.f2, "F3": Key.f3, "F4": Key.f4,
            "F5": Key.f5, "F6": Key.f6, "F7": Key.f7, "F8": Key.f8,
            "F9": Key.f9, "F10": Key.f10, "F11": Key.f11, "F12": Key.f12,
        }

        try:
            actual_key = special_keys.get(key, key)

            if action == "down":
                self._keyboard.press(actual_key)
            elif action == "up":
                self._keyboard.release(actual_key)
            elif action == "type":
                self._keyboard.type(key)
        except Exception as e:
            logging.error(f"Keyboard event error: {e}")

    def _handle_clipboard(self, data: Dict):
        """Handle clipboard sync."""
        if not PYPERCLIP_AVAILABLE:
            return

        action = data.get("action")

        try:
            if action == "set":
                text = data.get("text", "")
                pyperclip.copy(text)
            elif action == "get":
                text = pyperclip.paste()
                # Send clipboard content back
                asyncio.create_task(self._send_message({
                    "action": "clipboard_content",
                    "session_id": self.session_id,
                    "text": text,
                }))
        except Exception as e:
            logging.error(f"Clipboard error: {e}")

    def _set_quality(self, quality: str):
        """Change stream quality."""
        if self.video_track:
            self.video_track.set_quality(quality)
            self._quality = quality

    def _set_monitor(self, monitor_id: int):
        """Switch monitor."""
        if self.video_track:
            self.video_track.set_monitor(monitor_id)
            self._selected_monitor = monitor_id

    async def _send_message(self, message: Dict):
        """Send message via callback."""
        try:
            await self.send_callback(json.dumps(message))
        except Exception as e:
            logging.error(f"Failed to send message: {e}")

    async def stop(self):
        """Stop the remote desktop session."""
        self._running = False

        if self.video_track:
            self.video_track.stop()
            self.video_track = None

        if self.pc:
            await self.pc.close()
            self.pc = None

        logging.info(f"Remote desktop session {self.session_id} stopped")


# =============================================================================
# Public API Functions
# =============================================================================


def get_monitors() -> Dict[str, Any]:
    """Get list of available monitors."""
    if not MSS_AVAILABLE:
        return {"success": False, "error": "mss not available", "monitors": []}

    try:
        with mss.mss() as sct:
            monitors = []
            for i, mon in enumerate(sct.monitors):
                if i == 0:
                    continue
                monitors.append({
                    "id": i,
                    "left": mon["left"],
                    "top": mon["top"],
                    "width": mon["width"],
                    "height": mon["height"],
                    "name": f"Monitor {i}",
                    "primary": i == 1,
                })
            return {"success": True, "monitors": monitors}
    except Exception as e:
        return {"success": False, "error": str(e), "monitors": []}


async def start_remote_desktop(session_id: str, send_callback: Callable) -> Dict[str, Any]:
    """Start a new remote desktop session."""
    if session_id in active_sessions:
        await active_sessions[session_id].stop()

    session = RemoteDesktopSession(session_id, send_callback)
    result = await session.start()

    if result.get("success"):
        active_sessions[session_id] = session

    return result


async def stop_remote_desktop(session_id: str) -> Dict[str, Any]:
    """Stop a remote desktop session."""
    if session_id not in active_sessions:
        return {"success": False, "error": "Session not found"}

    await active_sessions[session_id].stop()
    del active_sessions[session_id]

    return {"success": True}


async def handle_webrtc_answer(session_id: str, answer: Dict) -> Dict[str, Any]:
    """Handle WebRTC answer from frontend."""
    if session_id not in active_sessions:
        return {"success": False, "error": "Session not found"}

    return await active_sessions[session_id].handle_answer(answer)


async def handle_ice_candidate(session_id: str, candidate: Dict) -> Dict[str, Any]:
    """Handle ICE candidate from frontend."""
    if session_id not in active_sessions:
        return {"success": False, "error": "Session not found"}

    return await active_sessions[session_id].handle_ice_candidate(candidate)


def check_dependencies() -> Dict[str, bool]:
    """Check which dependencies are available."""
    return {
        "mss": MSS_AVAILABLE,
        "aiortc": AIORTC_AVAILABLE,
        "pynput": PYNPUT_AVAILABLE,
        "pyperclip": PYPERCLIP_AVAILABLE,
        "all_required": MSS_AVAILABLE and AIORTC_AVAILABLE,
        "full_control": PYNPUT_AVAILABLE,
        "clipboard": PYPERCLIP_AVAILABLE,
    }
