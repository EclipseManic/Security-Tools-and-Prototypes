"""`python -m api.server` — local uvicorn entry point."""

from __future__ import annotations

import argparse
import os

import uvicorn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SOC trainer web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="", help="Override the sessions.db path")
    parser.add_argument(
        "--allow-lan",
        action="store_true",
        help="Allow binding to a non-loopback address (no TLS, single-user only)",
    )
    parser.add_argument("--reload", action="store_true", help="Reload on code changes")
    args = parser.parse_args(argv)

    loopback = {"127.0.0.1", "localhost", "::1"}
    if args.host not in loopback and not args.allow_lan:
        parser.error(
            "Refusing to bind to a non-loopback address without --allow-lan."
        )
    if args.db:
        os.environ["SOC_TRAINER_DB"] = args.db

    # The factory reads SOC_TRAINER_DB from the environment.
    uvicorn.run(
        "api.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
