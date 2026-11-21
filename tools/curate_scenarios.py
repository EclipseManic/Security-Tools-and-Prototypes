"""
tools/curate_scenarios.py
Apply the v4 domain taxonomy to the scenario library.

Usage:
    python tools/curate_scenarios.py --dry-run    # show keep/delete plan (default)
    python tools/curate_scenarios.py --apply --yes  # execute: move + retag + delete

What --apply does:
- keeps: rewrites the YAML `category:` field to the new domain display name
  and moves the file into scenarios/data/<domain_slug>/ (creating it)
- deletes: removes the file
- removes now-empty legacy dirs
- never touches scenarios/data/generated/ (generator output lives there)

Safety:
- dry-run prints the complete keep/delete list; nothing is written
- --apply refuses to run without --yes
- every kept file is validated to still load after retagging
"""

from __future__ import annotations

import sys
import shutil
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml

from core.taxonomy import DOMAINS, DOMAIN_BY_SLUG, domain_for, domain_name_for

DATA_DIR = ROOT / "scenarios" / "data"
SKIP_DIRS = {"generated"}

KEEP, DELETE, MOVED = "KEEP", "DELETE", "MOVED"


def scan() -> list[tuple[str, str, Path, str | None]]:
    """Return (verdict, domain_slug_or_None, yaml_path, category_dir)."""
    items: list[tuple[str, str, Path, str | None]] = []
    for path in sorted(DATA_DIR.rglob("*.yaml")):
        rel = path.relative_to(DATA_DIR)
        if rel.parts[0] in SKIP_DIRS:
            continue
        stem = path.stem
        cat_dir = rel.parts[0]
        slug = domain_for(cat_dir, stem)
        verdict = KEEP if slug else DELETE
        items.append((verdict, slug, path, cat_dir))
    return items


def _retag(path: Path, category_name: str) -> None:
    """Rewrite the YAML `category:` field in place."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Not a YAML mapping: {path}")
    if data.get("category") != category_name:
        data["category"] = category_name
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    return None


def _loadable(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return isinstance(data, dict) and bool(data.get("id")) and bool(data.get("category"))
    except Exception:
        return False


def _print_dry_run(items: list[tuple[str, str, Path, str | None]]) -> None:
    keeps = {slug: [] for slug in DOMAIN_BY_SLUG}
    deletes: list[Path] = []
    for verdict, slug, path, _cat in items:
        if verdict == KEEP:
            keeps[slug].append(path)
        else:
            deletes.append(path)

    print(f"=== CURATION DRY RUN — {DATA_DIR.relative_to(ROOT)} ===\n")
    total_kept = 0
    for domain in DOMAINS:
        files = keeps[domain.slug]
        total_kept += len(files)
        print(f"[{domain.slug}] {domain.name} — {len(files)}")
        for p in files:
            tag = "MOVE" if p.parent.name != domain.slug else "keep"
            print(f"   {tag:5} {p.name}")
        print()

    print(f"--- DELETE — {len(deletes)} files ---")
    for p in deletes:
        print(f"   del {p.relative_to(DATA_DIR)}")
    print()
    print(f"TOTAL: {len(items)} files  ->  KEEP {total_kept} / DELETE {len(deletes)}")
    print("Run with --apply --yes to execute this plan.")


def _backup_deletes(items: list[tuple[str, str, Path, str | None]]) -> Path:
    """Copy deleted files to scenarios_archive/<date>/ before deletion."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive = ROOT / "scenarios_archive" / stamp
    n = 0
    for verdict, _slug, path, _cat in items:
        if verdict != DELETE:
            continue
        dest = archive / path.relative_to(DATA_DIR)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        n += 1
    print(f"backed up {n} deleted files -> {archive.relative_to(ROOT)}")
    return archive


def _apply(items: list[tuple[str, str, Path, str | None]], backup: bool = False) -> None:
    kept = 0
    deleted = 0
    if backup:
        _backup_deletes(items)
    for verdict, slug, path, _cat in items:
        if verdict == KEEP:
            domain = DOMAIN_BY_SLUG[slug]
            dest_dir = DATA_DIR / domain.slug
            dest_dir.mkdir(exist_ok=True)
            _retag(path, domain.name)
            dest = dest_dir / path.name
            if path != dest:
                if dest.exists():
                    dest.unlink()
                path.rename(dest)
            if not _loadable(dest):
                raise RuntimeError(f"Retagged file failed to load: {dest}")
            if path.parent.name != domain.slug:
                print(f"moved  {path.relative_to(DATA_DIR)} -> {dest.relative_to(DATA_DIR)}")
            else:
                print(f"retagged {path.name} -> {domain.name}")
            kept += 1
        else:
            path.unlink()
            print(f"deleted {path.relative_to(DATA_DIR)}")
            deleted += 1

    removed = 0
    for legacy in sorted(DATA_DIR.iterdir()):
        if legacy.is_dir() and legacy.name not in SKIP_DIRS and legacy.name not in DOMAIN_BY_SLUG:
            leftovers = list(legacy.iterdir())
            if not leftovers:
                legacy.rmdir()
                removed += 1
            else:
                print(f"NOTE: legacy dir {legacy.name} still has files: {[p.name for p in leftovers]}")
    print(f"\nAPPLIED: kept {kept}, deleted {deleted}, removed {removed} empty dirs")
    print("Verification: re-scan + loader check...")
    verify()


def verify() -> None:
    items = scan()
    keeps = [i for i in items if i[0] == KEEP]
    assert len(items) == len(keeps), f"{len(items)} scanned, {len(keeps)} kept"
    for _v, slug, path, _c in keeps:
        assert path.parent.name == slug, f"{path} not in {slug}/"
        assert _loadable(path), f"unloadable: {path}"
    import scenarios.loader as loader
    by_cat = loader._load_yaml_scenarios()[0]
    names = {p.stem for p in DATA_DIR.rglob("*.yaml") if p.parent.name != "generated"}
    loaded = set()
    for cat, clss in by_cat.items():
        for cls in clss:
            loaded.add(cls._scenario_id)
    missing = names - loaded
    if missing:
        raise RuntimeError(f"YAMLs not loaded by loader: {missing}")
    print(f"Verification OK: {len(names)} YAMLs loaded, all in 7 domain dirs "
          f"({sorted(set(p.parent.name for p in DATA_DIR.rglob('*.yaml')))})")


def main() -> int:
    args = [a for a in sys.argv[1:] if a.startswith("--")]
    dry_run = "--apply" not in args
    confirm = "--yes" in args
    backup = "--backup" in args
    if not dry_run and not confirm:
        print("Refusing: --apply requires --yes")
        return 1

    items = scan()
    if dry_run:
        _print_dry_run(items)
        return 0

    print("Applying curation plan...\n")
    try:
        _apply(items, backup=backup)
    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
