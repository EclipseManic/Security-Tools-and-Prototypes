"""
tools/rebuild_mitre_map.py
Rebuild data/mitre_domain_map.json for the v4 7-domain taxonomy.

Unions the technique lists of absorbed legacy domains into each new domain,
drops removed domains (Physical Security, IoT / OT Security), and writes a
timestamped backup of the old map. Keys become the new display names so the
generator's domain validation stays consistent with core/taxonomy.py.

The script is idempotent and refuses to overwrite a map it cannot safely map:
re-running it on an already-rebuilt 7-domain map reports "up to date" instead
of writing an empty map (the old version did exactly that).

Usage:
    python tools/rebuild_mitre_map.py [--force] [--source PATH]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.taxonomy import (  # noqa: E402
    DOMAINS,
    DOMAIN_BY_SLUG,
    LEGACY_NAME_TO_DOMAIN,
)

MAP_PATH = ROOT / "data" / "mitre_domain_map.json"
BACKUP_DIR = ROOT / "data" / "backups"


def _slug_for_name(name: str) -> str | None:
    """Resolve both legacy and current domain names to a slug."""
    if name in DOMAIN_BY_SLUG:
        return name
    if name in LEGACY_NAME_TO_DOMAIN:
        return LEGACY_NAME_TO_DOMAIN[name]
    return None


def _load_map(path: Path) -> dict[str, list[str]]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return {str(k): [str(t) for t in v] for k, v in data.items()}


def rebuild(source: Path) -> tuple[dict[str, list[str]], list[str], list[str], bool]:
    """Return (new_map, dropped, unknown, changed)."""
    old_map = _load_map(source)
    new_map: dict[str, list[str]] = {d.name: [] for d in DOMAINS}
    dropped: list[str] = []
    unknown: list[str] = []

    for name, techniques in old_map.items():
        slug = _slug_for_name(name)
        if slug is None:
            dropped.append(name)
            continue
        if slug not in DOMAIN_BY_SLUG:
            unknown.append(name)
            continue
        domain = DOMAIN_BY_SLUG[slug]
        new_map[domain.name] = sorted(set(new_map[domain.name]) | set(techniques))

    normalized_old = {
        DOMAIN_BY_SLUG[_slug_for_name(name)].name: sorted(set(techniques))
        for name, techniques in old_map.items()
        if _slug_for_name(name) in DOMAIN_BY_SLUG
    }
    changed = new_map != normalized_old
    return new_map, dropped, unknown, changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild the MITRE domain map")
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help="Map to rebuild from (defaults to data/mitre_domain_map.json)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Write even when unknown domain keys would be dropped",
    )
    args = parser.parse_args(argv)

    source = args.source if args.source is not None else MAP_PATH
    if not source.exists():
        print(f"MITRE map not found: {source}", file=sys.stderr)
        return 1

    try:
        new_map, dropped, unknown, changed = rebuild(source)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Could not rebuild map: {exc}", file=sys.stderr)
        return 1

    if unknown:
        print(
            f"WARNING: unknown old domain keys would be dropped: {unknown}",
            file=sys.stderr,
        )
        if not args.force:
            print("Refusing to write. Re-run with --force if this is intended.", file=sys.stderr)
            return 2

    if not any(new_map.values()):
        print("Refusing to write an empty MITRE map.", file=sys.stderr)
        return 2

    if not changed:
        print(f"MITRE map already up to date: {MAP_PATH}")
        for name, techs in new_map.items():
            print(f"  {name}: {len(techs)} techniques")
        return 0

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = BACKUP_DIR / f"mitre_domain_map.{stamp}.json"
    shutil.copy2(source, backup)
    MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    MAP_PATH.write_text(json.dumps(new_map, indent=2), encoding="utf-8")

    print(f"MITRE map rebuilt -> {MAP_PATH}")
    for name, techs in new_map.items():
        print(f"  {name}: {len(techs)} techniques")
    if dropped:
        print(f"Dropped domains: {', '.join(dropped)}")
    print(f"Backup written to {backup}")

    # Sanity: the generator must load the same map from the shipped path.
    import core.scenario_generator as gen

    loaded = gen._DOMAIN_MITRE_MAP
    if loaded != new_map:
        print("WARNING: scenario_generator loaded a different map", file=sys.stderr)
        return 1
    print(f"scenario_generator OK — map loaded with {len(loaded)} domains")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
