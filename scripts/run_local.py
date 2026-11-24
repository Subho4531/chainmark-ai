"""
Local Development & Testing Runner for Chainmark AI.
Runs the Rust Proxy Gateway (port 8000) and the React Vite frontend (port 5173).

Usage:
    python scripts/run_local.py
    (or uv run python scripts/run_local.py)
"""

import subprocess
import sys
import signal
import time
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
RUST_BIN_DEBUG = ROOT / "target" / "debug" / "chainmark-proxy.exe"
RUST_BIN_RELEASE = ROOT / "target" / "release" / "chainmark-proxy.exe"


def main():
    print("=" * 65)
    print("   CHAINMARK AI: LOCAL TESTING ENVIRONMENT (RUST CORE)")
    print("   Backend Gateway:  http://localhost:8000")
    print("   Frontend Console: http://localhost:5173")
    print("=" * 65)

    env = os.environ.copy()
    cargo_bin = str(Path.home() / ".cargo" / "bin")
    mingw_bin = r"C:\Users\subho\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20261117-ucrt-x86_64\bin"
    if cargo_bin not in env.get("PATH", ""):
        env["PATH"] = f"{cargo_bin};{mingw_bin};{env.get('PATH', '')}"

    if RUST_BIN_RELEASE.exists():
        backend_cmd = [str(RUST_BIN_RELEASE)]
        print(f"[+] Launching Release Rust Proxy Gateway: {RUST_BIN_RELEASE}")
    elif RUST_BIN_DEBUG.exists():
        backend_cmd = [str(RUST_BIN_DEBUG)]
        print(f"[+] Launching Debug Rust Proxy Gateway: {RUST_BIN_DEBUG}")
    else:
        backend_cmd = ["cargo", "run", "-p", "chainmark-proxy"]
        print("[+] Launching Rust Proxy Gateway via `cargo run`...")

    frontend_cmd = ["npm", "run", "dev", "--prefix", str(FRONTEND_DIR)]

    backend_proc = subprocess.Popen(backend_cmd, cwd=ROOT, env=env)
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
