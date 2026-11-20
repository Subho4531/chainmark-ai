"""
Local Development & Testing Runner for Chainmark AI.
Runs the FastAPI proxy backend (port 8000) and the React Vite frontend (port 5173).

Usage (from any directory):
    uv run python scripts/run_local.py
"""

import subprocess
import sys
import signal
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"


def main():
    print("=" * 65)
    print("   CHAINMARK AI: LOCAL TESTING ENVIRONMENT")
    print("   Backend Gateway: http://localhost:8000")
    print("   Frontend Console: http://localhost:5173")
    print("=" * 65)

    backend_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "chainmark.interceptor.proxy:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        "--reload",
    ]
    frontend_cmd = ["npm", "run", "dev", "--prefix", str(FRONTEND_DIR)]

    backend_proc = subprocess.Popen(backend_cmd, cwd=ROOT)
    time.sleep(1)
    frontend_proc = subprocess.Popen(frontend_cmd, cwd=ROOT, shell=True)

    def shutdown(signum, frame):
        print("\n[+] Shutting down Chainmark local servers...")
        backend_proc.terminate()
        frontend_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
