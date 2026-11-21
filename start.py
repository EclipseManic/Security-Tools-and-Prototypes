"""
start.py — one-command launcher for the SOC Trainer web GUI.

Usage:
    python start.py                 # install/build if needed, then serve
    python start.py --port 9000
    python start.py --no-browser
    python start.py --build always  # force a frontend rebuild

It performs, in order:
  1. installs missing Python packages from requirements.txt
  2. installs npm dependencies if web/node_modules is missing/stale
  3. builds web/dist if it is missing or older than the frontend sources
  4. starts the FastAPI app (API + built SPA) and opens the browser
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
DIST_INDEX = WEB_DIR / "dist" / "index.html"
REQUIREMENTS = BASE_DIR / "requirements.txt"

REQUIRED_MODULES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "itsdangerous": "itsdangerous",
    "yaml": "pyyaml",
    "rich": "rich",
    "httpx": "httpx",
    "reportlab": "reportlab",
    "dotenv": "python-dotenv",
}

FRONTEND_SOURCES = [
    WEB_DIR / "src",
    WEB_DIR / "index.html",
    WEB_DIR / "package.json",
    WEB_DIR / "package-lock.json",
    WEB_DIR / "vite.config.ts",
    WEB_DIR / "tsconfig.json",
]


def log(message: str) -> None:
    print(message, flush=True)


def newest_mtime(paths: list[Path]) -> float:
    newest = 0.0
    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            newest = max(newest, path.stat().st_mtime)
            continue
        for file in path.rglob("*"):
            if file.is_file() and "node_modules" not in file.parts:
                newest = max(newest, file.stat().st_mtime)
    return newest


def npm_command() -> list[str] | None:
    """Return an invocable npm command, accounting for Windows .cmd shims."""
    if os.name == "nt":
        located = shutil.which("npm.cmd") or shutil.which("npm")
        return [located] if located else None
    located = shutil.which("npm")
    return [located] if located else None


def run(command: list[str], cwd: Path, label: str) -> bool:
    log(f"[setup] {label}...")
    try:
        completed = subprocess.run(command, cwd=str(cwd))
    except OSError as exc:
        log(f"[setup] failed: {exc}")
        return False
    if completed.returncode != 0:
        log(f"[setup] failed (exit {completed.returncode}).")
        return False
    return True


def ensure_python_deps(allow_install: bool) -> bool:
    missing = [
        package
        for module, package in REQUIRED_MODULES.items()
        if importlib.util.find_spec(module) is None
    ]
    if not missing:
        return True

    log(f"[setup] missing Python packages: {', '.join(sorted(set(missing)))}")
    if not allow_install:
        log(f"[setup] install them with: {sys.executable} -m pip install -r requirements.txt")
        return False
    if not run(
        [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)],
        BASE_DIR,
        "installing Python dependencies",
    ):
        return False
    return True


def ensure_frontend(build_mode: str, allow_install: bool) -> tuple[bool, str]:
    """Install npm deps and build the SPA when needed. Returns (ok, reason)."""
    npm = npm_command()
    node_modules = WEB_DIR / "node_modules"
    install_stamp = node_modules / ".soc-install-stamp"
    package_files = [WEB_DIR / "package.json", WEB_DIR / "package-lock.json"]

    needs_install = not node_modules.is_dir() or not install_stamp.exists()
    if not needs_install:
        needs_install = newest_mtime([p for p in package_files if p.exists()]) > install_stamp.stat().st_mtime

    needs_build = build_mode == "always" or not DIST_INDEX.exists()
    if build_mode == "auto" and not needs_build:
        needs_build = newest_mtime(FRONTEND_SOURCES) > DIST_INDEX.stat().st_mtime

    if build_mode == "never":
        if not DIST_INDEX.exists():
            return False, "web/dist is missing but --build never was requested"
        return True, ""
    if not needs_install and not needs_build:
        return True, ""

    if npm is None:
        return False, "Node.js/npm was not found on PATH. Install Node 18+ and re-run."

    if needs_install:
        if not allow_install:
            if node_modules.is_dir():
                needs_install = False  # existing modules are usable; skip the stamp check
            else:
                return False, "web/node_modules is missing; run `npm --prefix web install` or omit --no-install"
        if needs_install and not run(
            npm + ["install", "--no-audit", "--no-fund"],
            WEB_DIR,
            "installing frontend dependencies",
        ):
            return False, "npm install failed"
        try:
            install_stamp.touch()
        except OSError:
            pass

    if needs_build:
        if not run(npm + ["run", "build"], WEB_DIR, "building the browser app"):
            return False, "frontend build failed"

    return True, ""


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def open_when_ready(url: str, port: int) -> None:
    for _ in range(40):
        time.sleep(0.25)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                webbrowser.open(url)
                return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install/build the SOC Trainer and start the web GUI.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="", help="Override the sessions.db path")
    parser.add_argument("--allow-lan", action="store_true", help="Allow a non-loopback host")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser window")
    parser.add_argument("--no-install", action="store_true", help="Never run pip/npm install")
    parser.add_argument(
        "--build",
        choices=("auto", "always", "never"),
        default="auto",
        help="Frontend build policy (default: only when sources changed)",
    )
    args = parser.parse_args(argv)

    os.chdir(BASE_DIR)
    loopback = {"127.0.0.1", "localhost", "::1"}
    if args.host not in loopback and not args.allow_lan:
        parser.error("Refusing to bind to a non-loopback address without --allow-lan.")
    if not port_is_free(args.port):
        log(f"[error] Port {args.port} is already in use. Stop the other server or use --port.")
        return 1
    if not ensure_python_deps(allow_install=not args.no_install):
        return 1

    ok, reason = ensure_frontend(args.build, allow_install=not args.no_install)
    if not ok:
        log(f"[error] {reason}")
        return 1

    if args.db:
        os.environ["SOC_TRAINER_DB"] = args.db

    # Import after dependency installation so a first run works end to end.
    import uvicorn  # noqa: PLC0415

    from config import OPENROUTER_API_KEY, OPENROUTER_MODEL  # noqa: PLC0415
    from api.app import create_app  # noqa: PLC0415

    app = create_app()
    url = f"http://{'127.0.0.1' if args.host in loopback else args.host}:{args.port}"

    log("")
    log("=" * 62)
    log("  SOC Trainer — local training range")
    log(f"  GUI        : {url}")
    log(f"  API docs   : {url}/api/docs")
    if OPENROUTER_API_KEY:
        log(f"  AI debrief : enabled · {OPENROUTER_MODEL}")
    else:
        log("  AI debrief : offline (no key configured or disabled in Settings)")
    log("  Stop with Ctrl+C")
    log("=" * 62)
    log("")

    if not args.no_browser:
        threading.Thread(target=open_when_ready, args=(url, args.port), daemon=True).start()

    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    except KeyboardInterrupt:
        pass
    log("\n[stopped] SOC Trainer shut down.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
