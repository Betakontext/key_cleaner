#!/usr/bin/env python3
"""
clean_temp_key_cleaner.py
Löscht temporäre Ordner 'key_cleaner_*' im System-Temp-Verzeichnis (Windows, Linux, macOS).

Optionen:
  --list        Nur anzeigen, nicht löschen
  --force, -f   Ohne Rückfrage löschen
  --base PATH   Alternatives Temp-Basisverzeichnis angeben
"""

import argparse
import os
import shutil
import sys
from pathlib import Path
from datetime import datetime

def detect_temp_base() -> Path:
    # Bevorzugt TMPDIR/TEMP/TMP, sonst plattformspezifischer Default
    for var in ("TMPDIR", "TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            return Path(v)
    return Path(os.getenv("TMPDIR", "/tmp")) if os.name != "nt" else Path(os.environ.get("TEMP", r"C:\Windows\Temp"))

def human_ts(p: Path) -> str:
    try:
        ts = datetime.fromtimestamp(p.stat().st_mtime)
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"

def main():
    ap = argparse.ArgumentParser(description="Clean key_cleaner_* temp folders cross-platform.")
    ap.add_argument("--list", action="store_true", help="Nur auflisten, nichts löschen")
    ap.add_argument("--force", "-f", action="store_true", help="Ohne Rückfrage löschen")
    ap.add_argument("--base", type=str, default=None, help="Temp-Basispfad überschreiben")
    args = ap.parse_args()

    base = Path(args.base) if args.base else detect_temp_base()
    pattern = "key_cleaner_*"

    print(f"Temp base: {base}")
    if not base.exists():
        print("Basisverzeichnis existiert nicht. Ende.")
        sys.exit(0)

    targets = sorted(base.glob(pattern))
    targets = [p for p in targets if p.is_dir()]

    if not targets:
        print(f"Keine Ordner nach Muster {pattern} gefunden.")
        sys.exit(0)

    print("\nGefundene Ordner:")
    for d in targets:
        print(f"  {d}    (LastWrite: {human_ts(d)})")

    if args.list:
        print("\nNur Anzeige (--list). Keine Änderungen vorgenommen.")
        sys.exit(0)

    if not args.force:
        try:
            ans = input("\nLöschen? (y/N): ").strip().lower()
        except EOFError:
            ans = "n"
        if ans not in ("y", "yes", "j", "ja"):
            print("Abgebrochen. Keine Änderungen.")
            sys.exit(0)

    errors = 0
    for d in targets:
        try:
            print(f"Lösche {d}")
            shutil.rmtree(d, ignore_errors=False)
        except Exception as e:
            errors += 1
            print(f"Fehler beim Löschen von {d}: {e}")

    if errors:
        print(f"\nFertig mit {errors} Fehler(n).")
        sys.exit(1)
    else:
        print("\nFertig. Alle passenden Ordner wurden entfernt.")

if __name__ == "__main__":
    main()
