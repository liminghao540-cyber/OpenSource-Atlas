"""Windows launcher for the OpenSource Atlas local dashboard."""
from __future__ import annotations

import socket
import threading
import time
import webbrowser

from opensource_atlas.web import serve

URL = "http://127.0.0.1:8765"


def _open_when_ready() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 8765), timeout=0.5):
                webbrowser.open(URL)
                return
        except OSError:
            time.sleep(0.25)


if __name__ == "__main__":
    threading.Thread(target=_open_when_ready, daemon=True).start()
    print("OpenSource Atlas is starting. Keep this window open while using the dashboard.")
    print(f"Dashboard: {URL}")
    serve()
