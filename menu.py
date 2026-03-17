"""
menu.py – Interactive CLI launcher for FortiAnalyzer
Guides the user through log processing and dashboard generation.
"""

import os
import subprocess
from pathlib import Path

BASE_DIR    = Path(__file__).parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
INPUT_DIR   = BASE_DIR / "input"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def run(script: str):
    subprocess.run(["python", str(SCRIPTS_DIR / script)])


def list_logs():
    return sorted([f for f in INPUT_DIR.glob("*.log") if f.is_file()])


def menu():
    clear()
    print("=" * 55)
    print("   FortiAnalyzer  •  Fortigate Traffic Log Analyzer")
    print("=" * 55)
    print(f"\n  Project folder : {BASE_DIR}\n")

    # ── Step 1: Parse logs ────────────────────────────────────
    choice = input("Parse .log files now? (y/n): ").strip().lower()

    if choice == "y":
        logs = list_logs()

        if not logs:
            print("\n  [!] No .log files found in /input.")
            input("\nPress ENTER to continue...")
        else:
            print("\nAvailable files:\n")
            for i, f in enumerate(logs, start=1):
                print(f"  {i}) {f.name}")

            sel = input("\nEnter the file number to process: ").strip()

            if sel.isdigit() and 1 <= int(sel) <= len(logs):
                chosen = logs[int(sel) - 1]
                print(f"\n  Processing: {chosen.name}\n")
                run("fortianalyzer.py")
            else:
                print("\n  [!] Invalid selection. Skipping.")

    # ── Step 2: Generate dashboard ────────────────────────────
    choice = input("\nGenerate Excel dashboard now? (y/n): ").strip().lower()

    if choice == "y":
        print("\n  Building dashboard...\n")
        run("generate_dashboard.py")
        print("\n  Dashboard generated successfully!")

    print("\n  Done!")
    input("Press ENTER to exit...")


if __name__ == "__main__":
    menu()
