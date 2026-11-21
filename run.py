#!/usr/bin/env python3
"""File Intelligence Platform launcher.

Builds the React app when needed and serves the API and GUI from one process.
The server binds to loopback by default: the scanner can read any file the
process can access, so it is not safe to expose.

    python run.py                    # build if needed, serve at 127.0.0.1:8000
    python run.py --port 8770        # different port
    python run.py --no-browser       # do not open a browser
    python run.py --build always     # force a frontend rebuild
    python run.py --db ./fip.db     # different SQLite database
    python run.py --reset-db         # delete the default database first
    python run.py --dev              # Vite dev server + API (hot reload)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND_DIR = ROOT / "backend"
FRONTEND_DIR = ROOT / "frontend"
DIST_DIR = FRONTEND_DIR / "dist"
DEFAULT_DB = BACKEND_DIR / "data" / "fip.db"


def fail(message: str) -> None:
    print(f"[error] {message}", file=sys.stderr)
    raise SystemExit(1)


def run_npm(args: list[str]) -> None:
    npm = shutil.which("npm")
    if not npm:
        fail("Node.js and npm are required to build the browser app.")
    result = subprocess.run([npm, *args], cwd=FRONTEND_DIR)
    if result.returncode != 0:
        fail(f"npm {' '.join(args)} failed")


def frontend_needs_build() -> bool:
    index = DIST_DIR / "index.html"
    if not index.is_file():
        return True
    built_at = index.stat().st_mtime
    for path in (FRONTEND_DIR / "src").rglob("*"):
        if path.is_file() and path.stat().st_mtime > built_at:
            return True
    for name in ("package.json", "package-lock.json", "vite.config.ts", "index.html"):
        path = FRONTEND_DIR / name
        if path.is_file() and path.stat().st_mtime > built_at:
            return True
    return False


def ensure_frontend(mode: str) -> None:
    if mode == "never":
        if not (DIST_DIR / "index.html").is_file():
            fail("frontend/dist is missing and --build never was requested.")
        return
    if mode == "auto" and not frontend_needs_build():
        return

    print("[web] installing frontend dependencies...")
    run_npm(["install", "--no-audit", "--no-fund"])
    print("[web] building the browser app...")
    run_npm(["run", "build"])


def open_later(url: str) -> None:
    def _open() -> None:
        time.sleep(1.5)
        webbrowser.open(url)

    threading.Thread(target=_open, daemon=True).start()


def serve(host: str, port: int, db_path: str) -> None:
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(db_path).as_posix()}"
    os.environ["API_HOST"] = host
    os.environ["API_PORT"] = str(port)
    os.environ.setdefault("LOG_LEVEL", "INFO")
    sys.path.insert(0, str(BACKEND_DIR))

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        log_level=os.environ["LOG_LEVEL"].lower(),
    )


def serve_dev(host: str, port: int, db_path: str) -> None:
    npm = shutil.which("npm")
    if not npm:
        fail("Node.js and npm are required for --dev.")

    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(db_path).as_posix()}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR) + os.pathsep + env.get("PYTHONPATH", "")

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", host,
         "--port", str(port), "--reload"],
        cwd=BACKEND_DIR,
        env=env,
    )
    web = subprocess.Popen([npm, "run", "dev"], cwd=FRONTEND_DIR, env=env)

    print()
    print("=" * 60)
    print(f"  API : http://{host}:{port}/api/docs")
    print("  GUI : http://localhost:5173")
    print("  Press Ctrl+C to stop both.")
    print("=" * 60)
    print()

    try:
        while api.poll() is None and web.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for process in (api, web):
            if process.poll() is None:
                process.terminate()
        for process in (api, web):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the File Intelligence Platform locally.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite database path")
    parser.add_argument("--reset-db", action="store_true", help="Delete the database first")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser")
    parser.add_argument(
        "--build",
        choices=("auto", "always", "never"),
        default="auto",
        help="Frontend build policy (default: auto)",
    )
    parser.add_argument("--dev", action="store_true", help="Run Vite with hot reload")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    db_path = Path(args.db).expanduser().resolve()

    if args.reset_db and db_path.exists():
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(db_path) + suffix)
            if candidate.exists():
                candidate.unlink()
        print(f"[db] removed {db_path}")
    elif db_path.exists():
        print(f"[db] using {db_path} ({db_path.stat().st_size / 1024:.0f} KB)")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    if args.dev:
        serve_dev(args.host, args.port, str(db_path))
        return

    ensure_frontend(args.build)

    url = f"http://{args.host}:{args.port}/"
    print()
    print("=" * 60)
    print("  File Intelligence Platform")
    print(f"  GUI        : {url}")
    print(f"  API docs   : {url}api/docs")
    print(f"  Database   : {db_path}")
    print("  Stop with Ctrl+C")
    print("=" * 60)
    print()

    if not args.no_browser:
        open_later(url)

    serve(args.host, args.port, str(db_path))


if __name__ == "__main__":
    main()
