#!/usr/bin/env python3
"""Start the ServiceSentinel web console.

    python run.py                          # production server on 127.0.0.1:8765
    python run.py --port 9000              # different port
    python run.py --password "s3cret"      # require a login
    python run.py --no-browser             # do not open a browser
    python run.py --data-dir D:\\evidence   # different evidence folder
    python run.py --server dev --debug     # development server with reloader
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import os
import socket
import sys
import threading
import webbrowser
from pathlib import Path

from sentinel import APP_NAME, VERSION, create_app
from sentinel import config

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def is_admin() -> bool:
    if not config.IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - advisory only
        return False


def port_available(host: str, port: int) -> bool:
    # No SO_REUSEADDR: on Windows it lets a second socket bind to a port that
    # already has a listener, which would make this check always pass.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, port))
            return True
        except OSError:
            return False


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description=f"{APP_NAME} {VERSION} - Windows service inventory, hunting and triage console.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="port to listen on (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    parser.add_argument("--debug", action="store_true", help="enable Flask debug mode and the reloader")
    parser.add_argument("--data-dir", help="evidence directory (default: ServiceSentinelData beside run.py)")
    parser.add_argument("--password", help="require this password before the console opens")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit binding to a non-loopback address; requires --password",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        help=f"evidence retention in days (default {config.retention_days()})",
    )
    parser.add_argument(
        "--server",
        choices=["waitress", "dev"],
        default="waitress",
        help="WSGI server: waitress (default, production) or dev (Flask, debugging only)",
    )
    parser.add_argument("--workers", type=int, default=4, help="waitress worker threads (default 4)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    # Keep the startup banner visible when output is redirected (scheduled task,
    # service wrapper, CI) instead of buffered until exit.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except (ValueError, OSError):
            pass

    args = parse_args(argv)

    if args.data_dir:
        config.set_data_root(Path(args.data_dir).expanduser())
    if args.password:
        config.set_auth_password(args.password)
    if args.retention_days:
        os.environ["SENTINEL_RETENTION_DAYS"] = str(args.retention_days)

    if not config.IS_WINDOWS:
        print("[!] ServiceSentinel collects Windows service data. The interface will start, but")
        print("    live endpoints will report that collection is unavailable on this platform.")

    if not is_loopback(args.host) and not args.allow_remote:
        print(f"[!] Refusing to bind {args.host}: this console can change Windows services.")
        print("    Bind 127.0.0.1, or pass --allow-remote together with --password.")
        return 2
    if not is_loopback(args.host) and not config.auth_password():
        print("[!] A non-loopback bind requires --password so the console is not wide open.")
        return 2
    if not port_available(args.host, args.port):
        print(f"[!] Port {args.port} on {args.host} is already in use. Start with --port <other>.")
        return 2

    app = create_app()
    url = f"http://{args.host}:{args.port}/"
    elevated = is_admin()

    print(f"  {APP_NAME} {VERSION}")
    print(f"  Console      : {url}")
    print(f"  Evidence     : {config.data_root()}")
    print(f"  Host         : {socket.gethostname()}")
    print(f"  Elevation    : {'administrator' if elevated else 'standard user (some metadata is unreadable)'}")
    print(f"  Login        : {'password required' if config.auth_password() else 'OS account only (localhost)'}")
    print(f"  Retention    : {config.retention_days()} days")
    print(f"  Server       : {args.server}")
    print("  Stop         : Ctrl+C")
    print()

    if not elevated:
        print("  Tip          : run from an elevated prompt for complete service metadata.")
    if not config.PS_SCRIPT.exists():
        print(f"  [!] Collector script missing: {config.PS_SCRIPT}")
    print()

    if not args.no_browser and not args.debug:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        if args.server == "waitress" and not args.debug:
            try:
                from waitress import serve
            except ImportError:
                print("[!] waitress is not installed; falling back to the Flask development server.")
                print("    Install it with: pip install -r requirements.txt")
                app.run(host=args.host, port=args.port, threaded=True)
            else:
                serve(app, host=args.host, port=args.port, threads=max(2, args.workers))
        else:
            app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=args.debug, threaded=True)
    except KeyboardInterrupt:
        print("\nServiceSentinel stopped.")
    except OSError as exc:
        print(f"[!] Unable to start the server: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
