"""One-shot helper: nén project gửi Khánh Duy, loại trừ data thô / venv / secrets."""
from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(r"C:\Users\Administrator\OneDrive\Desktop\University_Threat_Detection")
OUTPUT_ZIP = Path(r"C:\Users\Administrator\OneDrive\Desktop\University_Threat_Detection_for_Duy_2026-06-15.zip")

EXCLUDE_DIR_NAMES = {"__pycache__", ".pytest_cache", ".ipynb_checkpoints", ".mypy_cache"}
EXCLUDE_REL_DIRS = {
    Path("data/raw"),
    Path(".venv"),
    Path(".git"),
    Path(".pytest_cache"),
}
EXCLUDE_REL_FILES = {
    Path(".env"),
    Path("CLAUDE.local.md"),
}
EXCLUDE_FILE_SUFFIXES = (".pyc",)


def is_excluded_dir(rel: Path) -> bool:
    parts = rel.parts
    if any(p in EXCLUDE_DIR_NAMES for p in parts):
        return True
    for excl in EXCLUDE_REL_DIRS:
        excl_parts = excl.parts
        if parts[: len(excl_parts)] == excl_parts:
            return True
    return False


def is_excluded_file(rel: Path) -> bool:
    if rel in EXCLUDE_REL_FILES:
        return True
    name = rel.name
    if name.endswith(":Zone.Identifier") or name.endswith("Zone.Identifier"):
        return True
    if name.lower().endswith(".zip"):
        return True
    if any(name.endswith(suf) for suf in EXCLUDE_FILE_SUFFIXES):
        return True
    return False


def human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def dir_size(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        rel_root = Path(root).relative_to(PROJECT_ROOT)
        dirs[:] = [d for d in dirs if not is_excluded_dir(rel_root / d)]
        for f in files:
            rel = rel_root / f
            if is_excluded_file(rel):
                continue
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


def preflight() -> int:
    print("=== TOP-LEVEL ITEMS GIỮ LẠI ===")
    total = 0
    for entry in sorted(PROJECT_ROOT.iterdir()):
        rel = entry.relative_to(PROJECT_ROOT)
        if entry.is_dir():
            if is_excluded_dir(rel):
                print(f"  SKIP  {rel}/")
                continue
            size = dir_size(entry)
            total += size
            print(f"  KEEP  {rel}/  ({human(size)})")
        else:
            if is_excluded_file(rel):
                print(f"  SKIP  {rel}")
                continue
            size = entry.stat().st_size
            total += size
            print(f"  KEEP  {rel}  ({human(size)})")
    print(f"\nTỔNG ước tính (uncompressed): {human(total)}")
    return total


def build_zip() -> tuple[int, int]:
    file_count = 0
    OUTPUT_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT_ZIP.exists():
        OUTPUT_ZIP.unlink()

    excluded_critical: list[str] = []

    with zipfile.ZipFile(OUTPUT_ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(PROJECT_ROOT):
            rel_root = Path(root).relative_to(PROJECT_ROOT)
            pruned = []
            kept = []
            for d in dirs:
                rel = (rel_root / d) if str(rel_root) != "." else Path(d)
                if is_excluded_dir(rel):
                    pruned.append(str(rel))
                else:
                    kept.append(d)
            dirs[:] = kept
            for p in pruned:
                if p in {"data\\raw", "data/raw", ".venv", ".git"}:
                    excluded_critical.append(p)

            for f in files:
                rel = (rel_root / f) if str(rel_root) != "." else Path(f)
                if is_excluded_file(rel):
                    continue
                abs_path = Path(root) / f
                arcname = (Path("University_Threat_Detection") / rel).as_posix()
                try:
                    zf.write(abs_path, arcname)
                    file_count += 1
                except OSError as e:
                    print(f"  WARN  could not add {rel}: {e}", file=sys.stderr)

    print(f"\nCritical exclusions hit during walk: {sorted(set(excluded_critical))}")
    return file_count, OUTPUT_ZIP.stat().st_size


def verify():
    print("\n=== VERIFY ===")
    forbidden_prefixes = (
        "University_Threat_Detection/data/raw/",
        "University_Threat_Detection/.venv/",
        "University_Threat_Detection/.git/",
    )
    forbidden_exact = {
        "University_Threat_Detection/.env",
        "University_Threat_Detection/CLAUDE.local.md",
    }
    bad = []
    with zipfile.ZipFile(OUTPUT_ZIP, "r") as zf:
        names = zf.namelist()
        for n in names:
            if n in forbidden_exact or any(n.startswith(p) for p in forbidden_prefixes):
                bad.append(n)
    print(f"Total entries trong zip: {len(names)}")
    if bad:
        print(f"!!! FOUND FORBIDDEN ENTRIES: {bad[:10]} ...")
        sys.exit(2)
    print("OK: data/raw/, .venv/, .git/, .env, CLAUDE.local.md đều KHÔNG có trong zip.")


def main():
    preflight()
    print("\n=== ZIPPING ===")
    count, size = build_zip()
    print(f"Wrote: {OUTPUT_ZIP}")
    print(f"Files : {count}")
    print(f"Size  : {human(size)}")
    verify()


if __name__ == "__main__":
    main()
